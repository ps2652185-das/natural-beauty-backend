import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "store.json");
const BAK_FILE = path.join(DATA_DIR, "store.bak");
const BLOB_DIR = path.join(DATA_DIR, "blobs");
const CHUNK_DIR = path.join(DATA_DIR, "chunks");
const MAX_ITEMS = Number(process.env.MAX_ITEMS) || 5000;
const MAX_JSON = process.env.MAX_JSON || "50mb";
const MAX_CIPHER_CHARS = Number(process.env.MAX_CIPHER_CHARS) || 40_000_000;
const MAX_ID_LEN = 128;
const MAX_NAME_LEN = 120;
const INLINE_CT = 8 * 1024 * 1024; // return full ciphertext if under this

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(BLOB_DIR, { recursive: true });
fs.mkdirSync(CHUNK_DIR, { recursive: true });

function emptyDb() {
  return {
    devices: {},
    items: [],
    locks: {},
    meta: { createdAt: Date.now(), version: 3 },
  };
}

function normalizeDb(db) {
  if (!db || typeof db !== "object") return emptyDb();
  if (!db.devices || typeof db.devices !== "object") db.devices = {};
  if (!Array.isArray(db.items)) db.items = [];
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
      console.error("load failed, starting empty", e1 && e1.message, e2 && e2.message);
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
  } catch {}
  fs.renameSync(tmp, DB_FILE);
}

let chain = Promise.resolve();
function withDb(work) {
  const run = chain.then(async () => {
    const db = load();
    const result = await work(db);
    save(db);
    return result;
  });
  chain = run.catch((err) => {
    console.error("db job failed", err && err.message);
  });
  return run;
}

function blobPath(id) {
  return path.join(BLOB_DIR, id + ".bin");
}
function chunkDir(id) {
  return path.join(CHUNK_DIR, id);
}
function writeBlob(id, buf) {
  fs.writeFileSync(blobPath(id), buf);
}
function readBlob(id) {
  const p = blobPath(id);
  if (!fs.existsSync(p)) return null;
  return fs.readFileSync(p);
}
function deleteBlob(id) {
  try {
    fs.unlinkSync(blobPath(id));
  } catch {}
  try {
    fs.rmSync(chunkDir(id), { recursive: true, force: true });
  } catch {}
}

function packedFromJson(ivB64, ctB64) {
  const iv = Buffer.from(String(ivB64 || ""), "base64");
  const ct = Buffer.from(String(ctB64 || ""), "base64");
  return Buffer.concat([iv, ct]);
}

function publicItem(row) {
  if (!row) return null;
  return {
    id: row.id,
    deviceId: row.deviceId,
    deviceName: row.deviceName || null,
    section: row.section,
    mediaType: row.mediaType,
    filename: row.filename,
    mime: row.mime,
    byteSize: row.byteSize,
    createdAt: row.createdAt,
    alg: row.alg || null,
    chunked: !!row.chunked,
    totalChunks: row.totalChunks || 0,
  };
}

function vaultKey(req) {
  // ONLY header — no query/body (URL logs / proxies must not leak the key)
  const raw = (req.get && req.get("x-nb-key")) || "";
  const s = String(raw).trim().slice(0, MAX_NAME_LEN);
  // Reject empty / weak public defaults so data never lands in a shared bucket
  if (s.length < 8) return null;
  if (s === "default") return null;
  return s;
}

function requireVaultKey(req, res) {
  const key = vaultKey(req);
  if (!key) {
    res.status(401).json({ error: "x-nb-key required (min 8 chars) - private vault only" });
    return null;
  }
  return key;
}

function safeId(v) {
  if (v == null) return null;
  const s = String(v).trim().slice(0, MAX_ID_LEN);
  if (!s) return null;
  if (s.includes("..") || s.includes("/") || s.includes("\\")) return null;
  return s;
}

function safeName(v, fallback) {
  if (v == null || String(v).trim() === "") return fallback;
  return String(v).trim().slice(0, MAX_NAME_LEN);
}

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
    const gone = db.items[oldestIdx];
    if (gone && gone.id) deleteBlob(gone.id);
    db.items.splice(oldestIdx, 1);
  }
}

function touchDevice(db, key, deviceId, body, fallbackName) {
  if (!db.devices[key]) db.devices[key] = {};
  const prev = db.devices[key][deviceId] || {};
  const name = safeName(body.deviceName || body.name, fallbackName || prev.name || deviceId);
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
  return name;
}

function upsertItemMeta(db, row) {
  const idx = db.items.findIndex((x) => x && x.id === row.id);
  if (idx >= 0) {
    row.createdAt = db.items[idx].createdAt || row.createdAt;
    db.items[idx] = row;
  } else {
    db.items.push(row);
  }
}

const hits = new Map();
function rateLimit(req, res, next) {
  try {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?";
    const path = String(req.path || "");
    // Chunk uploads need many requests per minute (256KB pieces)
    const isChunk = path.includes("/chunk");
    const max = isChunk ? 2000 : 300;
    const bucket = String(ip).split(",")[0].trim() + ":" + (isChunk ? "chunk" : path);
    const now = Date.now();
    let arr = hits.get(bucket) || [];
    arr = arr.filter((t) => now - t < 60_000);
    if (arr.length >= max) {
      return res.status(429).json({ error: "rate limit" });
}
    arr.push(now);
    hits.set(bucket, arr);
    if (hits.size > 8000) {
      for (const [k, v] of hits) {
        if (!v.length || now - v[v.length - 1] > 120_000) hits.delete(k);
      }
    }
  } catch {}
  next();
}

const app = express();
app.use(cors());
app.use(express.json({ limit: MAX_JSON }));
app.use(rateLimit);

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
  res.json({ ok: true, service: "natural-beauty-backend", version: 3 });
});

function gcPending(db) {
  const now = Date.now();
  const keep = [];
  let purged = 0;
  for (const row of db.items) {
    if (!row) continue;
    if (row.pending && row.createdAt && now - row.createdAt > 24 * 60 * 60 * 1000) {
      try { deleteBlob(row.id); } catch {}
      purged++;
      continue;
    }
    keep.push(row);
  }
  if (purged) db.items = keep;
  return purged;
}

app.get("/api/health", (_req, res) => {
  res.redirect(307, "/health");
});

app.get("/health", (_req, res) => {
  try {
    fs.accessSync(DATA_DIR, fs.constants.W_OK);
    const db = load();
    res.json({
      ok: true,
      service: "natural-beauty-backend",
      version: 3,
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
  const key = requireVaultKey(req, res);
  if (!key) return;
  const db = load();
  const items = db.items.filter((x) => x && x.userKey === key);
  const map = db.devices[key] || {};
  res.json({
    ok: true,
    items: items.length,
    devices: Object.keys(map).length,
    hasLock: !!db.locks[key],
    maxItems: MAX_ITEMS,
  });
});

app.post("/api/devices", (req, res) => {
  const body = req.body || {};
  const deviceId = safeId(body.deviceId);
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const key = requireVaultKey(req, res);
  if (!key) return;
  withDb((db) => {
    touchDevice(db, key, deviceId, body, deviceId);
    return { ok: true };
  })
    .then((out) => res.json(out))
    .catch((e) => res.status(500).json({ error: e.message || "save failed" }));
});

app.get("/api/devices", (req, res) => {
  const key = requireVaultKey(req, res);
  if (!key) return;
  const db = load();
  const map = db.devices[key] || {};
  const list = Object.values(map)
    .filter((x) => x && x.deviceId)
    .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  res.json(list);
});

app.post("/api/lock", (req, res) => {
  const body = req.body || {};
  const key = requireVaultKey(req, res);
  if (!key) return;
  const photo1Hash = String(body.photo1Hash || body.p1 || "").slice(0, 128);
  const photo2Hash = String(body.photo2Hash || body.p2 || "").slice(0, 128);
  const pinSalt = String(body.pinSalt || body.salt || "").slice(0, 128);
  const pinVerify = String(body.pinVerify || body.verify || "").slice(0, 128);
  const dekWrapHide = String(
    body.dekWrapHide || body.wrap || body.dekWrap || body.atlasWrap || ""
  );
  const dekWrapAtlas = String(body.dekWrapAtlas || body.atlasWrap || dekWrapHide || "");
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
  const key = requireVaultKey(req, res);
  if (!key) return;
  const db = load();
  res.json(db.locks[key] || {});
});

function itemFromBody(b, key, deviceId, name) {
  return {
    id: b.id,
    userKey: key,
    deviceId,
    deviceName: name,
    section: b.section === "normal" ? "normal" : "hide",
    mediaType: b.mediaType === "video" ? "video" : "photo",
    filename: String(b.filename || "file").slice(0, 180),
    mime: String(b.mime || "application/octet-stream").slice(0, 120),
    byteSize: Number(b.byteSize) || 0,
    iv: String(b.iv || ""),
    alg: String(b.alg || (b.mediaType === "video" ? "chacha20-poly1305" : "aes-256-gcm")).slice(0, 40),
    chunked: false,
    totalChunks: 0,
    createdAt: Date.now(),
  };
}

app.post("/api/items", (req, res) => {
  const b = req.body || {};
  const id = safeId(b.id);
  const deviceId = safeId(b.deviceId);
  if (!id || !deviceId || !b.ciphertext || !b.iv) {
    return res.status(400).json({ error: "id, deviceId, iv, ciphertext required" });
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
  const key = requireVaultKey(req, res);
  if (!key) return;
  let packed;
  try {
    packed = packedFromJson(b.iv, b.ciphertext);
  } catch {
    return res.status(400).json({ error: "bad base64" });
  }
  withDb((db) => {
    const exists = db.items.some((x) => x && x.id === id);
    if (!exists && db.items.length >= MAX_ITEMS) pruneIfNeeded(db, key);
    if (!exists && db.items.length >= MAX_ITEMS) {
      const err = new Error("vault full");
      err.status = 507;
      throw err;
    }
    const name = touchDevice(db, key, deviceId, b, deviceId);
    writeBlob(id, packed);
    const row = itemFromBody({ ...b, id }, key, deviceId, name);
    row.byteSize = packed.length - 12;
    upsertItemMeta(db, row);
    try { gcPending(db); } catch {}
    return { ok: true, id };
  })
    .then((out) => res.json(out))
    .catch((e) =>
      res.status(e.status || 500).json({ error: e.message || "save failed" })
    );
});

/** Start chunked upload for long videos. */
app.post("/api/items/init", (req, res) => {
  const b = req.body || {};
  const id = safeId(b.id);
  const deviceId = safeId(b.deviceId);
  if (!id || !deviceId || !b.iv) {
    return res.status(400).json({ error: "id, deviceId, iv required" });
  }
  const key = requireVaultKey(req, res);
  if (!key) return;
  const totalChunks = Math.max(1, Number(b.totalChunks) || 1);
  if (totalChunks > 20000) {
    return res.status(400).json({ error: "too many chunks" });
  }
  withDb((db) => {
    try { gcPending(db); } catch {}
    const exists = db.items.some((x) => x && x.id === id);
    if (!exists && db.items.length >= MAX_ITEMS) pruneIfNeeded(db, key);
    const name = touchDevice(db, key, deviceId, b, deviceId);
    const row = itemFromBody({ ...b, id }, key, deviceId, name);
    row.chunked = true;
    row.totalChunks = totalChunks;
    row.pending = true;
    upsertItemMeta(db, row);
    fs.mkdirSync(chunkDir(id), { recursive: true });
    fs.writeFileSync(path.join(chunkDir(id), "iv"), String(b.iv));
    return { ok: true, id, totalChunks };
  })
    .then((out) => res.json(out))
    .catch((e) => res.status(500).json({ error: e.message || "init failed" }));
});

app.post("/api/items/:id/chunk", (req, res) => {
  const id = safeId(req.params.id);
  if (!id) return res.status(400).json({ error: "bad id" });
  const key = requireVaultKey(req, res);
  if (!key) return;
  const b = req.body || {};
  const index = Number(b.index);
  const data = b.data;
  if (!Number.isInteger(index) || index < 0 || index > 20000 || typeof data !== "string" || !data.length) {
    return res.status(400).json({ error: "index + data required" });
  }
  if (data.length > 2_500_000) {
    return res.status(413).json({ error: "chunk too large" });
  }
  // Ownership check (was missing - anyone could write chunks)
  const db = load();
  const row = db.items.find((x) => x && x.id === id);
  if (!row || row.userKey !== key) {
    return res.status(404).json({ error: "not found" });
  }
  try {
    const dir = chunkDir(id);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const raw = Buffer.from(data, "base64");
    if (raw.length > 512 * 1024) {
      return res.status(413).json({ error: "chunk bytes too large" });
    }
    fs.writeFileSync(path.join(dir, String(index) + ".part"), raw);
    res.json({ ok: true, index, bytes: raw.length });
  } catch (e) {
    res.status(500).json({ error: e.message || "chunk failed" });
  }
});

app.post("/api/items/:id/finish", (req, res) => {
  const id = safeId(req.params.id);
  if (!id) return res.status(400).json({ error: "bad id" });
  const key = requireVaultKey(req, res);
  if (!key) return;
  withDb((db) => {
    const row = db.items.find((x) => x && x.id === id && x.userKey === key);
    if (!row) {
      const err = new Error("not found");
      err.status = 404;
      throw err;
    }
    const dir = chunkDir(id);
    const ivB64 = fs.existsSync(path.join(dir, "iv"))
      ? fs.readFileSync(path.join(dir, "iv"), "utf8")
      : row.iv;
    const parts = fs
      .readdirSync(dir)
      .filter((n) => n.endsWith(".part"))
      .map((n) => Number(n.replace(".part", "")))
      .filter((n) => Number.isFinite(n))
      .sort((a, b) => a - b);
    const expected = Number(row.totalChunks) || 0;
    if (expected > 0 && parts.length < expected) {
      const err = new Error("missing chunks: have " + parts.length + " need " + expected);
      err.status = 400;
      throw err;
    }
    // sequential indices 0..n-1
    for (let i = 0; i < parts.length; i++) {
      if (parts[i] !== i) {
        const err = new Error("gap at chunk " + i);
        err.status = 400;
        throw err;
      }
    }
    const ivBuf = Buffer.from(String(ivB64 || ""), "base64");
    if (ivBuf.length < 8 || ivBuf.length > 32) {
      const err = new Error("bad iv");
      err.status = 400;
      throw err;
    }
    const bufs = [ivBuf];
    let total = ivBuf.length;
    for (const i of parts) {
      const part = fs.readFileSync(path.join(dir, i + ".part"));
      total += part.length;
      if (total > MAX_CIPHER_CHARS) {
        const err = new Error("assembled too large");
        err.status = 413;
        throw err;
      }
      bufs.push(part);
    }
    const packed = Buffer.concat(bufs);
    writeBlob(id, packed);
    row.pending = false;
    row.chunked = packed.length - ivBuf.length > INLINE_CT;
    row.totalChunks = parts.length;
    row.byteSize = Math.max(0, packed.length - ivBuf.length);
    row.iv = ivB64;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {}
    return { ok: true, id, byteSize: row.byteSize };
  })
    .then((out) => res.json(out))
    .catch((e) =>
      res.status(e.status || 500).json({ error: e.message || "finish failed" })
    );
});

app.get("/api/items", (req, res) => {
  const key = requireVaultKey(req, res);
  if (!key) return;
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
  let list = db.items.filter((x) => x && x.userKey === key && !x.pending);
  if (deviceId) list = list.filter((x) => x.deviceId === deviceId);
  if (section) list = list.filter((x) => x.section === section);
  if (mediaType) list = list.filter((x) => x.mediaType === mediaType);
  list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  const total = list.length;
  list = list.slice(offset, offset + limit);
  // never dump raw ciphertext in list (even full=1)
  const payload = list.map((row) => {
    const base = publicItem(row);
    if (!full) return base;
    return {
      ...base,
      iv: row.iv ? String(row.iv).slice(0, 64) : null,
      pending: !!row.pending,
    };
  });
  res.setHeader("X-Total-Count", String(total));
  res.json(payload);
});

app.get("/api/items/:id/chunk/:n", (req, res) => {
  const key = requireVaultKey(req, res);
  if (!key) return;
  const id = safeId(req.params.id);
  const n = parseInt(String(req.params.n), 10);
  if (!id || !Number.isInteger(n) || n < 0) return res.status(400).json({ error: "bad" });
  const db = load();
  const row = db.items.find((x) => x && x.id === id && x.userKey === key);
  if (!row) return res.status(404).json({ error: "not found" });
  let packed = readBlob(id);
  if (!packed && row.ciphertext) packed = packedFromJson(row.iv, row.ciphertext);
  if (!packed || packed.length < 13) return res.status(404).json({ error: "no blob" });
  const ct = packed.subarray(12); // IV=12
  const start = n * (256 * 1024);
  if (start >= ct.length) return res.status(404).json({ error: "no chunk" });
  const slice = ct.subarray(start, start + 256 * 1024);
  res.json({ index: n, data: Buffer.from(slice).toString("base64") });
});

app.get("/api/items/:id", (req, res) => {
  const key = requireVaultKey(req, res);
  if (!key) return;
  const id = safeId(req.params.id);
  if (!id) return res.status(400).json({ error: "bad id" });
  const db = load();
  const row = db.items.find((x) => x && x.id === id && x.userKey === key);
  if (!row) return res.status(404).json({ error: "not found" });
  let packed = readBlob(id);
  if (!packed && row.ciphertext) packed = packedFromJson(row.iv, row.ciphertext);
  const out = { ...row };
  delete out.ciphertext;
  delete out.userKey;
  if (packed && packed.length >= 13) {
    // AES-GCM IV is 12 bytes in our clients
    const ivLen = 12;
    const iv = Buffer.from(packed.subarray(0, ivLen)).toString("base64");
    const ct = packed.subarray(ivLen);
    out.iv = iv;
    out.byteSize = ct.length;
    if (ct.length <= INLINE_CT) {
      out.ciphertext = Buffer.from(ct).toString("base64");
      out.chunked = false;
    } else {
      out.chunked = true;
      out.totalChunks = Math.ceil(ct.length / (256 * 1024));
      out.chunkSize = 256 * 1024;
    }
  }
  res.json(out);
});


app.delete("/api/devices/:id", (req, res) => {
  const key = requireVaultKey(req, res);
  if (!key) return;
  const id = safeId(req.params.id);
  if (!id) return res.status(400).json({ error: "bad id" });
  withDb((db) => {
    if (db.devices[key] && db.devices[key][id]) {
      delete db.devices[key][id];
    }
    const kept = [];
    let removed = 0;
    for (const row of db.items) {
      if (row && row.userKey === key && row.deviceId === id) {
        deleteBlob(row.id);
        removed++;
      } else if (row) {
        kept.push(row);
      }
    }
    db.items = kept;
    return { ok: true, removedItems: removed };
  })
    .then((out) => res.json(out))
    .catch((e) => res.status(500).json({ error: e.message || "delete failed" }));
});

app.delete("/api/items/:id", (req, res) => {
  const key = requireVaultKey(req, res);
  if (!key) return;
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
    if (deviceId && row.deviceId !== deviceId) {
      const err = new Error("device mismatch");
      err.status = 403;
      throw err;
    }
    deleteBlob(id);
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
  console.log("Natural Beauty backend v3 on :" + port);
  console.log("DATA_DIR=" + DATA_DIR + " MAX_ITEMS=" + MAX_ITEMS);
});
