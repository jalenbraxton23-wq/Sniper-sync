// Easy Money Sniper -- cross-device sync API, Phase 1.
// Real server-side login (unlike the client-side admin gate, this password
// check happens here, on the server, not in browser JS someone could read)
// plus get/save endpoints for the WNBA track record specifically -- the
// first data type being migrated off localStorage.
//
// Requires a D1 database bound as `env.DB` (set this up in the Worker's
// Settings -> Bindings after deploying).
//
// One-time setup: call POST /setup with {username, password} ONCE, before
// anyone else can. It only works while the users table is empty, so it
// can't be used to hijack the account later -- it's a one-shot bootstrap.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({ "Content-Type": "application/json" }, corsHeaders),
  });
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(derived)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32))).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function getUserFromToken(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return null;
  const token = auth.slice(7);
  const row = await env.DB.prepare("SELECT user_id FROM sessions WHERE token = ?").bind(token).first();
  return row ? row.user_id : null;
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);

    // ---- one-time bootstrap: only works while users table is empty.
    // GET version added specifically so it can be triggered by just
    // visiting a link on mobile, since opening a local HTML file to fire
    // a POST request turned out to be unreliable on iOS Safari. Query
    // params in a URL aren't as private as a POST body, but this endpoint
    // disables itself after the first successful call either way, so the
    // exposure window is exactly one use. ----
    if (url.pathname === "/setup" && (request.method === "POST" || request.method === "GET")) {
      const existing = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
      if (existing.c > 0) {
        return json({ error: "Setup already completed. Use /login instead." }, 403);
      }
      let username, password;
      if (request.method === "GET") {
        username = url.searchParams.get("username");
        password = url.searchParams.get("password");
      } else {
        const body = await request.json();
        username = body.username;
        password = body.password;
      }
      if (!username || !password) {
        return json({ error: "username and password required" }, 400);
      }
      const salt = randomToken();
      const hash = await hashPassword(password, salt);
      await env.DB.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(username, salt + ":" + hash)
        .run();
      return json({ ok: true, message: "Account created. Use /login now." });
    }

    // ---- login: real password check, happens here on the server ----
    if (url.pathname === "/login" && request.method === "POST") {
      const body = await request.json();
      const user = await env.DB.prepare("SELECT id, password_hash FROM users WHERE username = ?")
        .bind(body.username || "")
        .first();
      if (!user) return json({ error: "Invalid username or password" }, 401);
      const [salt, storedHash] = user.password_hash.split(":");
      const computedHash = await hashPassword(body.password || "", salt);
      if (computedHash !== storedHash) return json({ error: "Invalid username or password" }, 401);
      const token = randomToken();
      await env.DB.prepare("INSERT INTO sessions (token, user_id) VALUES (?, ?)").bind(token, user.id).run();
      return json({ ok: true, token: token });
    }

    // ---- get the shared WNBA track record -- PUBLIC, no login required.
    // Everyone who visits the site sees the exact same data, since this is
    // the app's own operational record, not something personal per visitor.
    if (url.pathname === "/wnba-tracker" && request.method === "GET") {
      const rows = await env.DB.prepare("SELECT date_key, data FROM wnba_pick_log").all();
      const log = {};
      (rows.results || []).forEach((r) => { log[r.date_key] = JSON.parse(r.data); });
      return json({ ok: true, log: log });
    }

    // ---- get the shared MLB track record -- same pattern as WNBA above ----
    if (url.pathname === "/mlb-tracker" && request.method === "GET") {
      const rows = await env.DB.prepare("SELECT date_key, data FROM mlb_pick_log").all();
      const log = {};
      (rows.results || []).forEach((r) => { log[r.date_key] = JSON.parse(r.data); });
      return json({ ok: true, log: log });
    }

    // ---- everything below here requires a valid session --
    // writing/updating the shared data is still admin-only
    const userId = await getUserFromToken(request, env);
    if (!userId) return json({ error: "Not logged in" }, 401);

    // ---- save/update one day's entry ----
    if (url.pathname === "/wnba-tracker" && request.method === "POST") {
      const body = await request.json();
      if (!body.dateKey || !body.entry) return json({ error: "dateKey and entry required" }, 400);
      await env.DB.prepare(
        "INSERT INTO wnba_pick_log (user_id, date_key, data, updated_at) VALUES (?, ?, ?, datetime('now')) " +
        "ON CONFLICT(user_id, date_key) DO UPDATE SET data = excluded.data, updated_at = datetime('now')"
      ).bind(userId, body.dateKey, JSON.stringify(body.entry)).run();
      return json({ ok: true });
    }

    // ---- delete one day's entry (the "X" button on a stuck day) ----
    if (url.pathname === "/wnba-tracker" && request.method === "DELETE" && url.searchParams.get("dateKey")) {
      await env.DB.prepare("DELETE FROM wnba_pick_log WHERE date_key = ?").bind(url.searchParams.get("dateKey")).run();
      return json({ ok: true });
    }

    // ---- reset everything ("Reset everything" button, last resort) ----
    if (url.pathname === "/wnba-tracker/reset-all" && request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM wnba_pick_log").run();
      return json({ ok: true });
    }

    // ---- MLB: same three write operations, mirrored exactly ----
    if (url.pathname === "/mlb-tracker" && request.method === "POST") {
      const body = await request.json();
      if (!body.dateKey || !body.entry) return json({ error: "dateKey and entry required" }, 400);
      await env.DB.prepare(
        "INSERT INTO mlb_pick_log (user_id, date_key, data, updated_at) VALUES (?, ?, ?, datetime('now')) " +
        "ON CONFLICT(user_id, date_key) DO UPDATE SET data = excluded.data, updated_at = datetime('now')"
      ).bind(userId, body.dateKey, JSON.stringify(body.entry)).run();
      return json({ ok: true });
    }

    if (url.pathname === "/mlb-tracker" && request.method === "DELETE" && url.searchParams.get("dateKey")) {
      await env.DB.prepare("DELETE FROM mlb_pick_log WHERE date_key = ?").bind(url.searchParams.get("dateKey")).run();
      return json({ ok: true });
    }

    if (url.pathname === "/mlb-tracker/reset-all" && request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM mlb_pick_log").run();
      return json({ ok: true });
    }

    return json({ error: "Not found" }, 404);
  },
};
