import { getStore } from "@netlify/blobs";

const STORE = "exus-keys";
const DURATIONS = {
  trial: 3 * 24 * 60 * 60 * 1000,
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
  permanent: null,
};
const CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function makeKey() {
  let s = "EXUS-";
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0) s += "-";
    s += CHARS[Math.floor(Math.random() * CHARS.length)];
  }
  return s;
}

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-admin-token",
    },
  });
}

function isAdmin(req) {
  const secret = process.env.ADMIN_TOKEN || "";
  return secret && req.headers.get("x-admin-token") === secret;
}

export default async (req) => {
  if (req.method === "OPTIONS") return json(204, {});
  if (req.method !== "POST") return json(405, { ok: false, error: "method" });

  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/+$/, "");
  let body = {};
  try { body = await req.json(); } catch {}

  const store = getStore(STORE);

  try {
    if (path === "generate") {
      if (!isAdmin(req)) return json(401, { ok: false, error: "auth" });
      const type = String(body.type || "daily");
      if (!(type in DURATIONS)) return json(400, { ok: false, error: "type" });
      const key = makeKey();
      const now = Date.now();
      const dur = DURATIONS[type];
      const record = {
        key, type, createdAt: now,
        expiresAt: dur === null ? null : now + dur,
        revoked: false, hwid: null, usedAt: null,
      };
      await store.setJSON(key, record);
      return json(200, { ok: true, key, record });
    }

    if (path === "validate") {
      const key = String(body.key || "").trim().toUpperCase();
      const hwid = String(body.hwid || "").trim();
      if (!key || !hwid) return json(400, { ok: false, error: "missing" });

      const k = await store.get(key, { type: "json" });
      if (!k) return json(200, { ok: false, error: "invalid" });
      if (k.revoked) return json(200, { ok: false, error: "revoked" });
      if (k.expiresAt && Date.now() > k.expiresAt) return json(200, { ok: false, error: "expired" });

      if (!k.hwid) {
        k.hwid = hwid; k.usedAt = Date.now();
        await store.setJSON(key, k);
        return json(200, { ok: true, type: k.type, expiresAt: k.expiresAt, bound: true });
      }
      if (k.hwid !== hwid) return json(200, { ok: false, error: "hwid" });
      return json(200, { ok: true, type: k.type, expiresAt: k.expiresAt, bound: false });
    }

    if (path === "revoke") {
      if (!isAdmin(req)) return json(401, { ok: false, error: "auth" });
      const key = String(body.key || "").trim().toUpperCase();
      if (!key) return json(400, { ok: false, error: "missing" });
      const k = await store.get(key, { type: "json" });
      if (!k) return json(404, { ok: false, error: "not found" });
      k.revoked = true;
      await store.setJSON(key, k);
      return json(200, { ok: true });
    }

    if (path === "list") {
      if (!isAdmin(req)) return json(401, { ok: false, error: "auth" });
      const { blobs } = await store.list();
      const out = [];
      for (const b of blobs) {
        const k = await store.get(b.key, { type: "json" });
        if (k) out.push(k);
      }
      out.sort((a, b) => b.createdAt - a.createdAt);
      return json(200, { ok: true, keys: out });
    }

    return json(404, { ok: false, error: "route" });
  } catch (e) {
    console.error(e);
    return json(500, { ok: false, error: "server", detail: String(e.message || e) });
  }
};
