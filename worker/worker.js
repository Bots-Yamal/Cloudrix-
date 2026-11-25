
const FRONTEND = "https://cloudrix0.pages.dev";
const CALLBACK = "https://cloudrix-auth.krissogonzalez22.workers.dev/callback";

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers }
  });
}

function cookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";").map(x => x.trim())
    .find(x => x.startsWith(name + "="));
  return item ? item.slice(name.length + 1) : null;
}

function randomHex(length = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function keyFrom(secret) {
  const hash = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(secret)
  );
  return crypto.subtle.importKey("raw", hash, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function seal(value, secret) {
  const key = await keyFrom(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(value));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return b64(iv) + "." + b64(encrypted);
}

async function unseal(value, secret) {
  const [ivText, dataText] = value.split(".");
  const decode = text => {
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, c => c.charCodeAt(0));
  };
  const key = await keyFrom(secret);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(ivText) }, key, decode(dataText)
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET || !env.SESSION_SECRET) {
      return json({ error: "Faltan secretos de configuración" }, 500);
    }

    if (url.pathname === "/login") {
      const state = randomHex();

      const github = new URL("https://github.com/login/oauth/authorize");
      github.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
      github.searchParams.set("redirect_uri", CALLBACK);
      github.searchParams.set("scope", "read:user");
      github.searchParams.set("state", state);

      return new Response(null, {
        status: 302,
        headers: {
          Location: github.toString(),
          "Set-Cookie": `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
        }
      });
    }

    if (url.pathname === "/callback") {
      const state = url.searchParams.get("state");
      const savedState = cookie(request, "oauth_state");
      const code = url.searchParams.get("code");

      if (!code || !state || !savedState || state !== savedState) {
        return new Response("Autorización inválida.", { status: 400 });
      }

      const tokenResponse = await fetch(
        "https://github.com/login/oauth/access_token",
        {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            client_id: env.GITHUB_CLIENT_ID,
            client_secret: env.GITHUB_CLIENT_SECRET,
            code
          })
        }
      );

      const tokenData = await tokenResponse.json();

      if (!tokenResponse.ok || !tokenData.access_token) {
        return new Response("No se pudo iniciar sesión.", { status: 400 });
      }

      const profileResponse = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "Cloudrix"
        }
      });

      if (!profileResponse.ok) {
        return new Response("No se pudo obtener el perfil.", { status: 400 });
      }

      const profile = await profileResponse.json();

      const session = await seal({
        login: profile.login,
        id: profile.id,
        avatar_url: profile.avatar_url,
        access_token: tokenData.access_token,
        expires: Date.now() + 7 * 24 * 60 * 60 * 1000
      }, env.SESSION_SECRET);

      return new Response(null, {
        status: 302,
        headers: [
          ["Location", FRONTEND + "/?github=connected"],
          ["Set-Cookie", `cloudrix_session=${session}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=604800`],
          ["Set-Cookie", "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"]
        ]
      });
    }

    if (url.pathname === "/api/me") {
      const sessionCookie = cookie(request, "cloudrix_session");
      if (!sessionCookie) return json({ error: "No hay sesión" }, 401);

      try {
        const session = await unseal(sessionCookie, env.SESSION_SECRET);
        if (session.expires < Date.now()) {
          return json({ error: "Sesión vencida" }, 401);
        }

        return json({
          id: session.id,
          login: session.login,
          avatar_url: session.avatar_url
        });
      } catch {
        return json({ error: "Sesión inválida" }, 401);
      }
    }

    if (url.pathname === "/logout") {
      return new Response(null, {
        status: 302,
        headers: [
          ["Location", FRONTEND],
          ["Set-Cookie", "cloudrix_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0"]
        ]
      });
    }

    return json({ error: "Ruta no encontrada" }, 404);
  }
};
