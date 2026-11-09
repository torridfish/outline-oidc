const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const { SignJWT, jwtVerify, exportJWK, generateKeyPair, importPKCS8 } = require("jose");

const ACCESS_TOKEN_TTL = "1h";
const REFRESH_TOKEN_TTL = "90d";
const ACCESS_TOKEN_EXPIRES_IN = 3600;

const app = express();
app.use((req, res, next) => {
  if (LOG_LEVEL === "debug") console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});
app.use(express.urlencoded({ extended: true }));

const PORT = 9000;
const LOG_LEVEL = (process.env.LOG_LEVEL || "info").toLowerCase();
const debug = LOG_LEVEL === "debug" ? console.log.bind(console) : () => {};
const INTERNAL_ISSUER = process.env.ISSUER || "http://oidc-proxy:9000";
const EXTERNAL_BASE = process.env.EXTERNAL_BASE;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_OAUTH_CLIENT_ID;
const TOKEN_AUDIENCE = process.env.OIDC_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_OAUTH_CLIENT_SECRET;
const GITHUB_OAUTH_CLIENT_ID = process.env.GITHUB_OAUTH_CLIENT_ID;
const GITHUB_OAUTH_CLIENT_SECRET = process.env.GITHUB_OAUTH_CLIENT_SECRET;
const OUTLINE_CALLBACK = process.env.OUTLINE_CALLBACK;
const ALLOWED_EMAILS_PATH = process.env.ALLOWED_EMAILS_PATH || "/data/allowed-emails.txt";
const SITE_NAME = process.env.SITE_NAME || "Outline";

const escapeHtml = (str) =>
  String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Fail fast on a broken configuration instead of failing at the first login.
const missing = [
  ["EXTERNAL_BASE", EXTERNAL_BASE],
  ["OUTLINE_CALLBACK", OUTLINE_CALLBACK],
  ["OIDC_CLIENT_ID", TOKEN_AUDIENCE],
].filter(([, v]) => !v).map(([k]) => k);
if (missing.length) {
  console.error(`Missing required env var(s): ${missing.join(", ")}`);
  process.exit(1);
}
if (!GITHUB_OAUTH_CLIENT_ID && !GOOGLE_CLIENT_ID) {
  console.error("No login provider configured: set GITHUB_OAUTH_CLIENT_ID/SECRET and/or GOOGLE_OAUTH_CLIENT_ID/SECRET");
  process.exit(1);
}
if ((GITHUB_OAUTH_CLIENT_ID && !GITHUB_OAUTH_CLIENT_SECRET) || (GOOGLE_CLIENT_ID && !GOOGLE_CLIENT_SECRET)) {
  console.error("A provider client ID is set without its client secret");
  process.exit(1);
}

// In-memory store for the login choice page session: sessionKey -> { outlineState, nonce }
const sessions = new Map();

// In-memory store for pending auth flows: proxyState -> { outlineState, nonce }
const pending = new Map();

// In-memory store for short-lived authorization codes: code -> userinfo
// (Access/refresh tokens are self-contained JWTs — not stored here.)
const codes = new Map();

let signingKey;
let verifyingKey;
let jwk;

async function signAccessToken(userinfo) {
  return new SignJWT({
    sub: userinfo.sub,
    email: userinfo.email,
    name: userinfo.name,
    picture: userinfo.picture,
    typ: "access",
  })
    .setProtectedHeader({ alg: "RS256", kid: "main" })
    .setIssuer(INTERNAL_ISSUER)
    .setAudience(TOKEN_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(ACCESS_TOKEN_TTL)
    .sign(signingKey);
}

async function signRefreshToken(userinfo) {
  return new SignJWT({
    sub: userinfo.sub,
    email: userinfo.email,
    name: userinfo.name,
    picture: userinfo.picture,
    typ: "refresh",
  })
    .setProtectedHeader({ alg: "RS256", kid: "main" })
    .setIssuer(INTERNAL_ISSUER)
    .setAudience(TOKEN_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(REFRESH_TOKEN_TTL)
    .sign(signingKey);
}

async function signIdToken(userinfo) {
  return new SignJWT({
    sub: userinfo.sub,
    email: userinfo.email,
    name: userinfo.name,
    picture: userinfo.picture,
    nonce: userinfo.nonce,
  })
    .setProtectedHeader({ alg: "RS256", kid: "main" })
    .setIssuer(INTERNAL_ISSUER)
    .setAudience(TOKEN_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(signingKey);
}

function loadAllowedEmails() {
  try {
    const content = fs.readFileSync(ALLOWED_EMAILS_PATH, "utf-8");
    return new Set(
      content
        .split("\n")
        .map((line) => line.trim().toLowerCase())
        .filter((line) => line && !line.startsWith("#"))
    );
  } catch {
    console.error("WARNING: Could not read allowed-emails.txt, denying all");
    return new Set();
  }
}

function renderChoicePage(sessionKey) {
  const providers = [];

  if (GOOGLE_CLIENT_ID) {
    providers.push(`
      <a class="btn google" href="/oidc-proxy/start/google?key=${sessionKey}">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
          <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
          <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
          <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
        </svg>
        Continue with Google
      </a>`);
  }

  if (GITHUB_OAUTH_CLIENT_ID) {
    providers.push(`
      <a class="btn github" href="/oidc-proxy/start/github?key=${sessionKey}">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor">
          <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
        </svg>
        Continue with GitHub
      </a>`);
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in to ${escapeHtml(SITE_NAME)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #1a1a1a;
      color: #e0e0e0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .card {
      background: #2a2a2a;
      border: 1px solid #3a3a3a;
      border-radius: 12px;
      padding: 40px;
      width: 360px;
      text-align: center;
    }
    h1 { font-size: 22px; margin-bottom: 8px; }
    .subtitle { font-size: 14px; color: #888; margin-bottom: 32px; }
    .btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      padding: 12px 20px;
      border-radius: 8px;
      text-decoration: none;
      font-size: 15px;
      font-weight: 500;
      transition: opacity 0.15s;
      margin-bottom: 12px;
    }
    .btn:hover { opacity: 0.85; }
    .google { background: #fff; color: #333; }
    .github { background: #24292f; color: #fff; border: 1px solid #444; }
    svg { width: 20px; height: 20px; flex-shrink: 0; }
  </style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(SITE_NAME)}</h1>
    <p class="subtitle">Choose how to sign in</p>
    ${providers.join("\n")}
  </div>
</body>
</html>`;
}

// --- JWKS (internal) ---
app.get("/jwks", (_req, res) => {
  res.json({ keys: [{ ...jwk, kid: "main", use: "sig", alg: "RS256" }] });
});

// --- Authorization endpoint: show login choice page ---
app.get("/oidc-proxy/authorize", (req, res) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  const outlineState = req.query.state || "";
  const nonce = req.query.nonce || "";

  const sessionKey = crypto.randomBytes(16).toString("hex");
  sessions.set(sessionKey, { outlineState, nonce });
  setTimeout(() => sessions.delete(sessionKey), 10 * 60 * 1000);
  debug(`[Authorize] Session created. key=${sessionKey}, sessions.size=${sessions.size}`);

  res.send(renderChoicePage(sessionKey));
});

// --- Start Google flow ---
app.get("/oidc-proxy/start/google", (req, res) => {
  const session = sessions.get(req.query.key);
  if (!session) {
    debug(`[Google] Session not found. key=${req.query.key}, sessions.size=${sessions.size}, keys=[${[...sessions.keys()].join(",")}]`);
    return res.status(400).send("Invalid or expired session. Please go back and try again.");
  }
  debug(`[Google] Session found. key=${req.query.key}`);
  sessions.delete(req.query.key);

  const proxyState = crypto.randomBytes(16).toString("hex");
  pending.set(proxyState, { outlineState: session.outlineState, nonce: session.nonce });
  setTimeout(() => pending.delete(proxyState), 10 * 60 * 1000);

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: `${EXTERNAL_BASE}/callback`,
    response_type: "code",
    scope: "openid profile email",
    state: proxyState,
    prompt: "select_account",
  });

  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// --- Start GitHub flow ---
app.get("/oidc-proxy/start/github", (req, res) => {
  const session = sessions.get(req.query.key);
  if (!session) {
    debug(`[GitHub] Session not found. key=${req.query.key}, sessions.size=${sessions.size}, keys=[${[...sessions.keys()].join(",")}]`);
    return res.status(400).send("Invalid or expired session. Please go back and try again.");
  }
  debug(`[GitHub] Session found. key=${req.query.key}`);
  sessions.delete(req.query.key);

  const proxyState = crypto.randomBytes(16).toString("hex");
  pending.set(proxyState, { outlineState: session.outlineState, nonce: session.nonce });
  setTimeout(() => pending.delete(proxyState), 10 * 60 * 1000);

  const params = new URLSearchParams({
    client_id: GITHUB_OAUTH_CLIENT_ID,
    redirect_uri: `${EXTERNAL_BASE}/github/callback`,
    scope: "user:email read:user",
    state: proxyState,
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

// --- Google callback (browser-facing, via cloudflared) ---
app.get("/oidc-proxy/callback", async (req, res) => {
  const { code, state: proxyState } = req.query;

  const flow = pending.get(proxyState);
  if (!flow) {
    return res.status(400).send("Invalid or expired state");
  }
  pending.delete(proxyState);

  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: `${EXTERNAL_BASE}/callback`,
        grant_type: "authorization_code",
      }),
    });

    const tokens = await tokenRes.json();
    if (tokens.error) {
      return res.status(400).send(`Google token error: ${tokens.error_description || tokens.error}`);
    }

    const userinfoRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const userinfo = await userinfoRes.json();
    const email = (userinfo.email || "").toLowerCase();

    const allowed = loadAllowedEmails();
    if (!allowed.has(email)) {
      console.log(`DENIED (Google): ${email} not in allowlist`);
      return res.status(403).send(
        `Access denied: ${email} is not in the allowed list. Please contact admin.`
      );
    }

    console.log(`ALLOWED (Google): ${email}`);

    const ourCode = crypto.randomBytes(32).toString("hex");
    codes.set(ourCode, {
      email: userinfo.email,
      name: userinfo.name,
      picture: userinfo.picture,
      sub: userinfo.sub,
      nonce: flow.nonce,
    });
    setTimeout(() => codes.delete(ourCode), 5 * 60 * 1000);

    const params = new URLSearchParams({
      code: ourCode,
      state: flow.outlineState,
    });
    res.redirect(`${OUTLINE_CALLBACK}?${params}`);
  } catch (err) {
    console.error("Google callback error:", err);
    res.status(500).send("Authentication failed");
  }
});

// --- GitHub callback ---
app.get("/oidc-proxy/github/callback", async (req, res) => {
  const { code, state: proxyState } = req.query;

  const flow = pending.get(proxyState);
  if (!flow) {
    return res.status(400).send("Invalid or expired state");
  }
  pending.delete(proxyState);

  try {
    const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
      },
      body: new URLSearchParams({
        client_id: GITHUB_OAUTH_CLIENT_ID,
        client_secret: GITHUB_OAUTH_CLIENT_SECRET,
        code,
        redirect_uri: `${EXTERNAL_BASE}/github/callback`,
      }),
    });

    const tokens = await tokenRes.json();
    if (tokens.error) {
      return res.status(400).send(`GitHub token error: ${tokens.error_description || tokens.error}`);
    }

    const [userinfoRes, emailsRes] = await Promise.all([
      fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
          "User-Agent": "outline-oidc-proxy",
        },
      }),
      fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
          "User-Agent": "outline-oidc-proxy",
        },
      }),
    ]);

    const userinfo = await userinfoRes.json();
    const emails = await emailsRes.json();

    // Prefer primary verified email
    const primaryEmail =
      (Array.isArray(emails) && emails.find((e) => e.primary && e.verified)?.email) ||
      userinfo.email;

    if (!primaryEmail) {
      return res
        .status(400)
        .send("Could not retrieve your email from GitHub. Please make sure your GitHub email is verified and visible.");
    }

    const email = primaryEmail.toLowerCase();

    const allowed = loadAllowedEmails();
    if (!allowed.has(email)) {
      console.log(`DENIED (GitHub): ${email} not in allowlist`);
      return res.status(403).send(
        `Access denied: ${email} is not in the allowed list. Please contact admin.`
      );
    }

    console.log(`ALLOWED (GitHub): ${email}`);

    const ourCode = crypto.randomBytes(32).toString("hex");
    codes.set(ourCode, {
      email: primaryEmail,
      name: userinfo.name || userinfo.login,
      picture: userinfo.avatar_url,
      sub: `github:${userinfo.id}`,
      nonce: flow.nonce,
    });
    setTimeout(() => codes.delete(ourCode), 5 * 60 * 1000);

    const params = new URLSearchParams({
      code: ourCode,
      state: flow.outlineState,
    });
    res.redirect(`${OUTLINE_CALLBACK}?${params}`);
  } catch (err) {
    console.error("GitHub callback error:", err);
    res.status(500).send("Authentication failed");
  }
});

// --- Token endpoint ---
app.post("/token", async (req, res) => {
  const { grant_type, code, refresh_token } = req.body;

  // Refresh flow
  if (grant_type === "refresh_token") {
    if (!refresh_token) {
      return res.status(400).json({ error: "invalid_request", error_description: "refresh_token missing" });
    }
    let payload;
    try {
      ({ payload } = await jwtVerify(refresh_token, verifyingKey, {
        issuer: INTERNAL_ISSUER,
        audience: TOKEN_AUDIENCE,
      }));
    } catch (err) {
      debug(`[Token refresh] verify failed: ${err.message}`);
      return res.status(400).json({ error: "invalid_grant" });
    }
    if (payload.typ !== "refresh") {
      return res.status(400).json({ error: "invalid_grant", error_description: "not a refresh token" });
    }

    // Re-check allowlist so revoked users can't keep refreshing
    const allowed = loadAllowedEmails();
    if (!allowed.has(String(payload.email || "").toLowerCase())) {
      console.log(`REFRESH DENIED: ${payload.email} not in allowlist`);
      return res.status(400).json({ error: "invalid_grant", error_description: "access revoked" });
    }

    const userinfo = {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
    };
    const newAccess = await signAccessToken(userinfo);
    const newRefresh = await signRefreshToken(userinfo);
    debug(`[Token refresh] issued new tokens for ${userinfo.email}`);
    return res.json({
      access_token: newAccess,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_EXPIRES_IN,
      refresh_token: newRefresh,
    });
  }

  // Authorization code flow (default; some clients omit grant_type)
  const userinfo = codes.get(code);
  if (!userinfo) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  codes.delete(code);

  const idToken = await signIdToken(userinfo);
  const accessToken = await signAccessToken(userinfo);
  const refreshToken = await signRefreshToken(userinfo);

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_EXPIRES_IN,
    refresh_token: refreshToken,
    id_token: idToken,
  });
});

// --- Userinfo endpoint ---
app.get("/userinfo", async (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) {
    return res.status(401).json({ error: "invalid_token" });
  }
  let payload;
  try {
    ({ payload } = await jwtVerify(token, verifyingKey, {
      issuer: INTERNAL_ISSUER,
      audience: TOKEN_AUDIENCE,
    }));
  } catch (_err) {
    return res.status(401).json({ error: "invalid_token" });
  }
  if (payload.typ !== "access") {
    return res.status(401).json({ error: "invalid_token" });
  }
  res.json({
    sub: payload.sub,
    email: payload.email,
    name: payload.name,
    picture: payload.picture,
  });
});

async function loadOrGenerateKeyPair() {
  const envKey = process.env.OIDC_PROXY_SIGNING_KEY;
  if (envKey) {
    let pem;
    try {
      pem = Buffer.from(envKey, "base64").toString("utf-8");
    } catch (err) {
      throw new Error(`OIDC_PROXY_SIGNING_KEY is set but not valid base64: ${err.message}`);
    }
    if (!pem.includes("BEGIN") || !pem.includes("PRIVATE KEY")) {
      throw new Error("OIDC_PROXY_SIGNING_KEY did not decode to a PEM private key");
    }
    const privateKey = await importPKCS8(pem, "RS256");
    const publicKey = crypto.createPublicKey(privateKey);
    console.log("Loaded persistent signing key from OIDC_PROXY_SIGNING_KEY");
    return { privateKey, publicKey };
  }
  console.warn(
    "WARNING: OIDC_PROXY_SIGNING_KEY not set — generating ephemeral key. " +
    "All tokens will be invalidated on restart. " +
    "Generate with: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM | base64 -w0"
  );
  return generateKeyPair("RS256");
}

// --- Start ---
(async () => {
  const kp = await loadOrGenerateKeyPair();
  signingKey = kp.privateKey;
  verifyingKey = kp.publicKey;
  jwk = await exportJWK(kp.publicKey);

  app.listen(PORT, () => {
    console.log(`OIDC proxy listening on port ${PORT}`);
    console.log(`Issuer: ${INTERNAL_ISSUER}`);
    console.log(`Allowed emails: ${ALLOWED_EMAILS_PATH}`);
    console.log(`Providers: ${[GOOGLE_CLIENT_ID && "Google", GITHUB_OAUTH_CLIENT_ID && "GitHub"].filter(Boolean).join(", ")}`);
  });
})();
