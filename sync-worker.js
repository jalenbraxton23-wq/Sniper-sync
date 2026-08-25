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

// converts American odds to decimal odds so two American numbers (one
// positive, one negative) can be compared on the same scale -- higher
// decimal odds always means a better payout for the bettor
function americanToDecimal(american) {
  if (american == null) return null;
  return american > 0 ? (american / 100) + 1 : (100 / Math.abs(american)) + 1;
}

// SportsGameOdds player IDs look like "ESTEURY_RUIZ_1_MLB" -- strip the
// trailing index and league, title-case the rest into a real display name
function parsePlayerName(playerID) {
  const parts = playerID.split("_");
  const nameParts = parts.slice(0, -2); // drop the "1" and "MLB" at the end
  return nameParts
    .map((p) => p.charAt(0) + p.slice(1).toLowerCase())
    .join(" ");
}

function normalizeName(name) {
  return name.toUpperCase().replace(/[^A-Z]/g, "");
}

function pickBest(dk, fd, dkLink, fdLink) {
  const dkDecimal = americanToDecimal(dk);
  const fdDecimal = americanToDecimal(fd);
  if (dkDecimal == null && fdDecimal == null) return { book: null, odds: null, link: null };
  if (dkDecimal != null && (fdDecimal == null || dkDecimal >= fdDecimal)) return { book: "draftkings", odds: dk, link: dkLink };
  return { book: "fanduel", odds: fd, link: fdLink };
}

// five confirmed-real MLB prop categories, mapped to their real SportsGameOdds
// statID -- NRFI/YRFI intentionally excluded, since it's confirmed not to
// exist as a market on this provider at all (checked their full stat catalog,
// not just one game's sample), so it stays as our own projection-only
// section on the site, untouched by any of this
const MLB_MARKET_STAT_IDS = {
  "batting_homeRuns": "home_run",
  "pitching_strikeouts": "strikeouts",
  "batting_hits+runs+rbi": "hits_runs_rbi",
  "batting_totalBases": "total_bases",
  "batting_stolenBases": "stolen_bases",
};

// pulls real prop odds from SportsGameOdds (DraftKings + FanDuel only,
// matching what the free tier actually has) across all five confirmed
// categories in one fetch, and stores just the cleaned-up result -- not
// the full raw payload, to stay well within the free tier's monthly
// object budget (objects are counted per event returned, not per market,
// so one fetch of the whole slate costs about as many objects as there
// are games, regardless of how many stat types we pull out of it)
async function refreshMlbOdds(env) {
  const apiKey = env.SGO_API_KEY;
  if (!apiKey) {
    console.error("SGO_API_KEY not set");
    return;
  }
  const res = await fetch(
    "https://api.sportsgameodds.com/v2/events?leagueID=MLB&oddsAvailable=true&apiKey=" + apiKey
  );
  if (!res.ok) {
    console.error("SportsGameOdds fetch failed", res.status);
    return;
  }
  const data = await res.json();
  const events = (data && data.data) || [];

  // build an in-memory map first, keyed by marketType+playerNameKey, merging
  // the "over"/"yes" and "under" sides as we encounter them, before writing
  // anything to the database
  const rows = {};

  events.forEach((event) => {
    const odds = event.odds || {};
    Object.keys(odds).forEach((key) => {
      const o = odds[key];
      if (!o || !o.playerID) return;
      const marketType = MLB_MARKET_STAT_IDS[o.statID];
      if (!marketType) return;

      const displayName = parsePlayerName(o.playerID);
      if (!displayName) return;
      const nameKey = normalizeName(displayName);
      const rowKey = marketType + "|" + nameKey;

      if (!rows[rowKey]) {
        rows[rowKey] = {
          marketType: marketType, nameKey: nameKey, name: displayName,
          betType: o.betTypeID, line: null,
          dkOver: null, fdOver: null, dkUnder: null, fdUnder: null,
          dkOverLink: null, fdOverLink: null, dkUnderLink: null, fdUnderLink: null,
        };
      }
      const row = rows[rowKey];
      const byBookmaker = o.byBookmaker || {};
      const dk = byBookmaker.draftkings ? parseInt(byBookmaker.draftkings.odds, 10) : null;
      const fd = byBookmaker.fanduel ? parseInt(byBookmaker.fanduel.odds, 10) : null;
      const dkLink = byBookmaker.draftkings ? byBookmaker.draftkings.deeplink : null;
      const fdLink = byBookmaker.fanduel ? byBookmaker.fanduel.deeplink : null;
      // the real line value lives under bookOverUnder (the actual
      // sportsbook's number), not a field literally called "line" --
      // fairOverUnder is SGO's own estimate, used only as a fallback if
      // no real book line is present for this specific odds entry
      const realLine = o.bookOverUnder != null ? Number(o.bookOverUnder) : (o.fairOverUnder != null ? Number(o.fairOverUnder) : null);

      // "yn" (yes/no) markets like home runs only have one real side we
      // care about -- store it in the "over" slot, same shape as an O/U
      // market with just one side filled in
      if (o.betTypeID === "yn" && o.sideID === "yes") {
        row.dkOver = dk; row.fdOver = fd; row.dkOverLink = dkLink; row.fdOverLink = fdLink;
      } else if (o.betTypeID === "ou" && o.sideID === "over") {
        row.dkOver = dk; row.fdOver = fd; row.dkOverLink = dkLink; row.fdOverLink = fdLink; if (realLine != null) row.line = realLine;
      } else if (o.betTypeID === "ou" && o.sideID === "under") {
        row.dkUnder = dk; row.fdUnder = fd; row.dkUnderLink = dkLink; row.fdUnderLink = fdLink; if (realLine != null) row.line = realLine;
      }
    });
  });

  // full-refresh: clear the old snapshot, insert the new one -- this table
  // only ever holds "right now's" odds, not history
  await env.DB.prepare("DELETE FROM mlb_odds").run();
  for (const key of Object.keys(rows)) {
    const r = rows[key];
    const bestOver = pickBest(r.dkOver, r.fdOver, r.dkOverLink, r.fdOverLink);
    const bestUnder = pickBest(r.dkUnder, r.fdUnder, r.dkUnderLink, r.fdUnderLink);
    await env.DB.prepare(
      "INSERT INTO mlb_odds (market_type, player_name_key, player_name, bet_type, line, dk_odds_over, fd_odds_over, dk_odds_under, fd_odds_under, best_book_over, best_odds_over, best_link_over, best_book_under, best_odds_under, best_link_under, updated_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))"
    ).bind(
      r.marketType, r.nameKey, r.name, r.betType, r.line,
      r.dkOver, r.fdOver, r.dkUnder, r.fdUnder,
      bestOver.book, bestOver.odds, bestOver.link, bestUnder.book, bestUnder.odds, bestUnder.link
    ).run();
  }
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

    // ---- get real DK/FanDuel odds across all five confirmed prop
    // categories, refreshed a few times a day by the scheduled cron job
    // below -- public, no login required, same as everything else the app
    // displays to every visitor ----
    if (url.pathname === "/mlb-odds" && request.method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT market_type, player_name_key, player_name, bet_type, line, dk_odds_over, fd_odds_over, dk_odds_under, fd_odds_under, best_book_over, best_odds_over, best_link_over, best_book_under, best_odds_under, best_link_under, updated_at FROM mlb_odds"
      ).all();
      const byMarket = {};
      (rows.results || []).forEach((r) => {
        if (!byMarket[r.market_type]) byMarket[r.market_type] = {};
        byMarket[r.market_type][r.player_name_key] = {
          name: r.player_name, betType: r.bet_type, line: r.line,
          dkOver: r.dk_odds_over, fdOver: r.fd_odds_over,
          dkUnder: r.dk_odds_under, fdUnder: r.fd_odds_under,
          bestBookOver: r.best_book_over, bestOddsOver: r.best_odds_over, bestLinkOver: r.best_link_over,
          bestBookUnder: r.best_book_under, bestOddsUnder: r.best_odds_under, bestLinkUnder: r.best_link_under,
          updatedAt: r.updated_at,
        };
      });
      return json({ ok: true, markets: byMarket });
    }

    // ---- get one of the generic trackers (NRFI/YRFI, Strikeouts, HR
    // Weather) -- same "public read" rule as WNBA/MLB above ----
    const getTrackerMatch = url.pathname.match(/^\/tracker\/([a-z]+)$/);
    if (getTrackerMatch && ["nrfi", "strikeout", "hrweather"].includes(getTrackerMatch[1]) && request.method === "GET") {
      const rows = await env.DB.prepare("SELECT date_key, data FROM generic_pick_log WHERE tracker_type = ?")
        .bind(getTrackerMatch[1]).all();
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

    // ---- generic tracker endpoints for NRFI/YRFI, Strikeouts, and HR
    // Weather -- one shared table with a `tracker_type` column, since these
    // three already used one parameterized pattern in the app itself rather
    // than three separate dedicated setups the way MLB/WNBA did ----
    const trackerMatch = url.pathname.match(/^\/tracker\/([a-z]+)$/);
    const trackerResetMatch = url.pathname.match(/^\/tracker\/([a-z]+)\/reset-all$/);
    const validTrackers = ["nrfi", "strikeout", "hrweather"];

    if (trackerMatch && validTrackers.includes(trackerMatch[1]) && request.method === "POST") {
      const trackerType = trackerMatch[1];
      const body = await request.json();
      if (!body.dateKey || !body.entry) return json({ error: "dateKey and entry required" }, 400);
      await env.DB.prepare(
        "INSERT INTO generic_pick_log (user_id, tracker_type, date_key, data, updated_at) VALUES (?, ?, ?, ?, datetime('now')) " +
        "ON CONFLICT(tracker_type, date_key) DO UPDATE SET data = excluded.data, updated_at = datetime('now')"
      ).bind(userId, trackerType, body.dateKey, JSON.stringify(body.entry)).run();
      return json({ ok: true });
    }

    if (trackerMatch && validTrackers.includes(trackerMatch[1]) && request.method === "DELETE" && url.searchParams.get("dateKey")) {
      await env.DB.prepare("DELETE FROM generic_pick_log WHERE tracker_type = ? AND date_key = ?")
        .bind(trackerMatch[1], url.searchParams.get("dateKey")).run();
      return json({ ok: true });
    }

    if (trackerResetMatch && validTrackers.includes(trackerResetMatch[1]) && request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM generic_pick_log WHERE tracker_type = ?").bind(trackerResetMatch[1]).run();
      return json({ ok: true });
    }

    // ---- manually trigger the odds refresh right now, for testing --
    // requires login, same as other write actions. The real, ongoing
    // refresh happens automatically via the cron trigger below.
    if (url.pathname === "/admin/refresh-mlb-odds" && request.method === "POST") {
      await refreshMlbOdds(env);
      return json({ ok: true, message: "Refreshed." });
    }

    return json({ error: "Not found" }, 404);
  },

  // runs on the cron schedule set in the Worker's Triggers tab -- fetches
  // real odds a few times a day and saves a clean snapshot, so the app
  // never calls SportsGameOdds directly (which would multiply requests by
  // however many visitors are on the site at once)
  async scheduled(event, env, ctx) {
    ctx.waitUntil(refreshMlbOdds(env));
  },
};
