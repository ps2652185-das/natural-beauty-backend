import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "store.json");
const BAK_FILE = path.join(DATA_DIR, "store.bak");
const MAX_ITEMS = Number(process.env.MAX_ITEMS) || 5000;
const MAX_JSON = process.env.MAX_JSON || "50mb";
const MAX_CIPHER_CHARS = Number(process.env.MAX_CIPHER_CHARS) || 40_000_000; // ~40MB string
const MAX_ID_LEN = 128;
const MAX_NAME_LEN = 120;

fs.mkdirSync(DATA_DIR, { recursive: true });

function emptyDb() {
  return {
    devices: {},
    items: [],
    locks: {},
    meta: { createdAt: Date.now(), version: 2 },
  };
}

function normalizeDb(db) {
  if (!db || typeof db !== "object") return emptyDb();
  if (!db.devices || typeof db.devices !== "object") db.devices = {};
  if (!Array.isArray(db.items)) db.items = [];
  // drop null holes
  db.items = db.items.filter((x) => x && typeof x === "object" && x.id);
  if (!db.locks || typeof db.locks !== "object") db.locks = {};
  if (!db.meta || typeof db.meta !== "object") db.meta = { createdAt: Date.now() };
  return db;
}

function load() {
  try {
    const raw = fs.readFileSync(DB_FILE, "utf8");
    return normalizeDb(JSON.parse(raw));
  } catch (e1) {
    try {
      const raw = fs.readFileSync(BAK_FILE, "utf8");
      console.warn("recovered from store.bak after primary load failure");
      return normalizeDb(JSON.parse(raw));
    } catch (e2) {
      console.error(
        "load failed, starting empty",
        e1 && e1.message,
        e2 && e2.message
      );
      return emptyDb();
    }
  }
}

function save(db) {
  const tmp = DB_FILE + ".tmp." + process.pid;
  const payload = JSON.stringify(db);
  fs.writeFileSync(tmp, payload, { encoding: "utf8" });
  try {
    if (fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, BAK_FILE);
  } catch {
    /* bak optional */
  }
  fs.renameSync(tmp, DB_FILE);
}

/** Single-flight write queue — prevents lost updates under concurrent POSTs. */
let chain = Promise.resolve();
function withDb(work) {
  const run = chain.then(async () => {
    const db = load();
    const result = await work(db);
    save(db);
    return result;
  });
  // Keep chain alive even on failure so later jobs still run
  chain = run.catch((err) => {
    console.error("db job failed", err && err.message);
  });
  return run;
}

function publicItem(row) {
  if (!row) return null;
  return {
    id: row.id,
    userKey: row.userKey,
    deviceId: row.deviceId,
    deviceName: row.deviceName || null,
    section: row.section,
    mediaType: row.mediaType,
    filename: row.filename,
    mime: row.mime,
    byteSize: row.byteSize,
    createdAt: row.createdAt,
  };
}

function vaultKey(req) {
  const raw =
    (req.get && req.get("x-nb-key")) ||
    (req.query && (req.query.key || req.query.userKey)) ||
    (req.body && (req.body.key || req.body.userKey)) ||
    "default";
  return String(raw).trim().slice(0, MAX_NAME_LEN) || "default";
}

function safeId(v) {
  if (v == null) return null;
  const s = String(v).trim().slice(0, MAX_ID_LEN);
  if (!s) return null;
  // block path tricks
  if (s.includes("..") || s.includes("/") || s.includes("\\")) return null;
  return s;
}

function safeName(v, fallback) {
  if (v == null || String(v).trim() === "") return fallback;
  return String(v).trim().slice(0, MAX_NAME_LEN);
}

/** Drop oldest items when over capacity (prefer same userKey). */
function pruneIfNeeded(db, key) {
  let guard = 0;
  while (db.items.length > MAX_ITEMS && guard++ < MAX_ITEMS + 10) {
    let oldestIdx = -1;
    let oldestAt = Infinity;
    for (let i = 0; i < db.items.length; i++) {
      const it = db.items[i];
      if (!it) continue;
      const t = it.createdAt || 0;
      if (it.userKey === key && t < oldestAt) {
        oldestAt = t;
        oldestIdx = i;
      }
    }
    if (oldestIdx < 0) {
      oldestAt = Infinity;
      for (let i = 0; i < db.items.length; i++) {
        const it = db.items[i];
        if (!it) continue;
        const t = it.createdAt || 0;
        if (t < oldestAt) {
          oldestAt = t;
          oldestIdx = i;
        }
      }
    }
    if (oldestIdx < 0) break;
    db.items.splice(oldestIdx, 1);
  }
}

/** Very light in-memory rate limit (per IP + route family). */
const hits = new Map();
function rateLimit(req, res, next) {
  try {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?";
    const bucket = String(ip).split(",")[0].trim() + ":" + (req.path || "");
    const now = Date.now();
    let arr = hits.get(bucket) || [];
    arr = arr.filter((t) => now - t < 60_000);
    if (arr.length >= 180) {
      return res.status(429).json({ error: "rate limit" });
    }
    arr.push(now);
    hits.set(bucket, arr);
    if (hits.size > 5000) {
      // crude GC
      for (const [k, v] of hits) {
        if (!v.length || now - v[v.length - 1] > 120_000) hits.delete(k);
      }
    }
  } catch {
    /* never block on limiter bugs */
  }
  next();
}

const app = express();
app.use(cors());
app.use(express.json({ limit: MAX_JSON }));
app.use(rateLimit);

// JSON parse / body errors
app.use((err, _req, res, next) => {
  if (err && err.type === "entity.too.large") {
    return res.status(413).json({ error: "payload too large" });
  }
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(400).json({ error: "invalid json" });
  }
  next(err);
});

app.get("/", (_req, res) => {
  res.json({ ok: true, service: "natural-beauty-backend", version: 2 });
});

app.get("/health", (_req, res) => {
  try {
    fs.accessSync(DATA_DIR, fs.constants.W_OK);
    const db = load();
    res.json({
      ok: true,
      service: "natural-beauty-backend",
      writable: true,
      items: db.items.length,
      maxItems: MAX_ITEMS,
      devices: Object.keys(db.devices).length,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

app.get("/api/stats", (req, res) => {
  const key = vaultKey(req);
  const db = load();
  const items = db.items.filter((x) => x && x.userKey === key);
  const map = db.devices[key] || {};
  res.json({
    ok: true,
    key,
    items: items.length,
    devices: Object.keys(map).length,
    hasLock: !!db.locks[key],
    maxItems: MAX_ITEMS,
  });
});

/** Device pulse — name optional. */
app.post("/api/devices", (req, res) => {
  const body = req.body || {};
  const deviceId = safeId(body.deviceId);
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const name = safeName(body.name, deviceId);
  const key = vaultKey(req);
  withDb((db) => {
    if (!db.devices[key]) db.devices[key] = {};
    const prev = db.devices[key][deviceId] || {};
    db.devices[key][deviceId] = {
      deviceId,
      name,
      model:
        body.model != null ? String(body.model).slice(0, MAX_NAME_LEN) : prev.model || "",
      batteryPct:
        body.batteryPct != null && Number.isFinite(Number(body.batteryPct))
          ? Number(body.batteryPct)
          : prev.batteryPct,
      updatedAt: Date.now(),
    };
    return { ok: true };
  })
    .then((out) => res.json(out))
    .catch((e) => res.status(500).json({ error: e.message || "save failed" }));
});

app.get("/api/devices", (req, res) => {
  const key = vaultKey(req);
  const db = load();
  const map = db.devices[key] || {};
  const list = Object.values(map)
    .filter((x) => x && x.deviceId)
    .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  res.json(list);
});

/**
 * Lock — accepts every field shape the apps send:
 *   dekWrapHide | wrap | dekWrap | atlasWrap
 *   photo1Hash | p1, photo2Hash | p2
 *   pinSalt | salt, pinVerify | verify
 */
app.post("/api/lock", (req, res) => {
  const body = req.body || {};
  const key = vaultKey(req);
  const photo1Hash = String(body.photo1Hash || body.p1 || "").slice(0, 128);
  const photo2Hash = String(body.photo2Hash || body.p2 || "").slice(0, 128);
  const pinSalt = String(body.pinSalt || body.salt || "").slice(0, 128);
  const pinVerify = String(body.pinVerify || body.verify || "").slice(0, 128);
  const dekWrapHide = String(
    body.dekWrapHide || body.wrap || body.dekWrap || body.atlasWrap || ""
  );
  const dekWrapAtlas = String(
    body.dekWrapAtlas || body.atlasWrap || dekWrapHide || ""
  );
  const atlasSalt = String(body.atlasSalt || pinSalt || "").slice(0, 128);
  const atlasVerify = String(body.atlasVerify || pinVerify || "").slice(0, 128);

  if (!photo1Hash || !photo2Hash || !dekWrapHide) {
    return res.status(400).json({
      error: "missing lock fields (need photo hashes + dek wrap)",
    });
  }
  withDb((db) => {
    const prev = db.locks[key];
    if (
      prev &&
      prev.pinVerify &&
      pinVerify &&
      prev.pinVerify !== pinVerify &&
      !body.force
    ) {
      const err = new Error("lock exists");
      err.status = 409;
      throw err;
    }
    db.locks[key] = {
      photo1Hash,
      photo2Hash,
      pinSalt,
      pinVerify,
      dekWrapHide,
      dekWrapAtlas,
      atlasSalt,
      atlasVerify,
      wrap: dekWrapHide,
      salt: pinSalt,
      verify: pinVerify,
      p1: photo1Hash,
      p2: photo2Hash,
      updatedAt: Date.now(),
    };
    return { ok: true };
  })
    .then((out) => res.json(out))
    .catch((e) =>
      res.status(e.status || 500).json({ error: e.message || "save failed" })
    );
});

app.get("/api/lock", (req, res) => {
  const key = vaultKey(req);
  const db = load();
  res.json(db.locks[key] || null);
});

app.post("/api/items", (req, res) => {
  const b = req.body || {};
  const id = safeId(b.id);
  const deviceId = safeId(b.deviceId);
  if (!id || !deviceId || !b.ciphertext || !b.iv) {
    return res
      .status(400)
      .json({ error: "id, deviceId, iv, ciphertext required" });
  }
  if (typeof b.ciphertext !== "string" || typeof b.iv !== "string") {
    return res.status(400).json({ error: "iv and ciphertext must be strings" });
  }
  if (!b.iv.length || !b.ciphertext.length) {
    return res.status(400).json({ error: "iv/ciphertext empty" });
  }
  if (b.ciphertext.length > MAX_CIPHER_CHARS) {
    return res.status(413).json({ error: "ciphertext too large" });
  }
  const key = vaultKey(req);
  withDb((db) => {
    const exists = db.items.some((x) => x && x.id === id);
    if (!exists && db.items.length >= MAX_ITEMS) {
      pruneIfNeeded(db, key);
    }
    if (!exists && db.items.length >= MAX_ITEMS) {
      const err = new Error("vault full");
      err.status = 507;
      throw err;
    }
    if (!db.devices[key]) db.devices[key] = {};
    const prevDev = db.devices[key][deviceId] || {};
    const devName = safeName(b.deviceName, prevDev.name || deviceId);
    db.devices[key][deviceId] = {
      deviceId,
      name: devName,
      model:
        b.model != null
          ? String(b.model).slice(0, MAX_NAME_LEN)
          : prevDev.model || "",
      batteryPct:
        b.batteryPct != null && Number.isFinite(Number(b.batteryPct))
          ? Number(b.batteryPct)
          : prevDev.batteryPct,
      updatedAt: Date.now(),
    };
    const row = {
      id,
      userKey: key,
      deviceId,
      deviceName: devName,
      section: b.section === "normal" ? "normal" : "hide",
      mediaType: b.mediaType === "video" ? "video" : "photo",
      filename: String(b.filename || "file").slice(0, 180),
      mime: String(b.mime || "application/octet-stream").slice(0, 120),
      byteSize: Number(b.byteSize) || 0,
      iv: b.iv,
      ciphertext: b.ciphertext,
      createdAt: Date.now(),
    };
    const idx = db.items.findIndex((x) => x && x.id === row.id);
    if (idx >= 0) {
      row.createdAt = db.items[idx].createdAt || row.createdAt;
      db.items[idx] = row;
    } else {
      db.items.push(row);
    }
    return { ok: true, id: row.id };
  })
    .then((out) => res.json(out))
    .catch((e) =>
      res.status(e.status || 500).json({ error: e.message || "save failed" })
    );
});

app.get("/api/items", (req, res) => {
  const key = vaultKey(req);
  const deviceId = req.query.deviceId ? safeId(req.query.deviceId) : null;
  const section = req.query.section;
  const mediaType = req.query.mediaType;
  const full = req.query.full === "1" || req.query.full === "true";
  let limit = parseInt(String(req.query.limit || "500"), 10);
  if (!Number.isFinite(limit) || limit < 1) limit = 500;
  if (limit > 2000) limit = 2000;
  let offset = parseInt(String(req.query.offset || "0"), 10);
  if (!Number.isFinite(offset) || offset < 0) offset = 0;

  const db = load();
  let list = db.items.filter((x) => x && x.userKey === key);
  if (deviceId) list = list.filter((x) => x.deviceId === deviceId);
  if (section) list = list.filter((x) => x.section === section);
  if (mediaType) list = list.filter((x) => x.mediaType === mediaType);
  list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  const total = list.length;
  list = list.slice(offset, offset + limit);
  const payload = full ? list : list.map(publicItem);
  res.setHeader("X-Total-Count", String(total));
  res.json(payload);
});

app.get("/api/items/:id", (req, res) => {
  const key = vaultKey(req);
  const id = safeId(req.params.id);
  if (!id) return res.status(400).json({ error: "bad id" });
  const db = load();
  const row = db.items.find((x) => x && x.id === id && x.userKey === key);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row);
});

app.delete("/api/items/:id", (req, res) => {
  const key = vaultKey(req);
  const id = safeId(req.params.id);
  if (!id) return res.status(400).json({ error: "bad id" });
  const deviceId =
    (req.query && safeId(req.query.deviceId)) ||
    (req.body && safeId(req.body.deviceId)) ||
    null;
  withDb((db) => {
    const row = db.items.find((x) => x && x.id === id);
    if (!row) return { ok: true, removed: 0 };
    if (row.userKey !== key) {
      const err = new Error("forbidden");
      err.status = 403;
      throw err;
    }
    // deviceId filter only when client sends it
    if (deviceId && row.deviceId !== deviceId) {
      const err = new Error("device mismatch");
      err.status = 403;
      throw err;
    }
    db.items = db.items.filter((x) => x && x.id !== id);
    return { ok: true, removed: 1 };
  })
    .then((out) => res.json(out))
    .catch((e) =>
      res.status(e.status || 500).json({ error: e.message || "save failed" })
    );
});

app.use((err, _req, res, _next) => {
  console.error(err);
  if (res.headersSent) return;
  res.status(500).json({ error: "server error" });
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log("Natural Beauty backend on :" + port);
  console.log("DATA_DIR=" + DATA_DIR + " MAX_ITEMS=" + MAX_ITEMS);
});
