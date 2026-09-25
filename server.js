import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "store.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

function load() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch {
    return { devices: {}, items: [], locks: {} };
  }
}

function save(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db));
}

const app = express();
app.use(cors());
app.use(express.json({ limit: "12mb" }));

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "natural-beauty-backend" });
});

app.post("/api/devices", (req, res) => {
  const { deviceId, name, userKey } = req.body || {};
  if (!deviceId || !name) return res.status(400).json({ error: "deviceId and name required" });
  const db = load();
  const key = userKey || "default";
  if (!db.devices[key]) db.devices[key] = {};
  db.devices[key][deviceId] = { deviceId, name, updatedAt: Date.now() };
  save(db);
  res.json({ ok: true });
});

app.get("/api/devices", (req, res) => {
  const key = req.query.userKey || "default";
  const db = load();
  const map = db.devices[key] || {};
  const list = Object.values(map).sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  res.json(list);
});

app.post("/api/lock", (req, res) => {
  const body = req.body || {};
  const key = body.userKey || "default";
  if (!body.photo1Hash || !body.photo2Hash || !body.dekWrapHide) {
    return res.status(400).json({ error: "missing lock fields" });
  }
  const db = load();
  db.locks[key] = {
    photo1Hash: body.photo1Hash,
    photo2Hash: body.photo2Hash,
    pinSalt: body.pinSalt,
    pinVerify: body.pinVerify,
    dekWrapHide: body.dekWrapHide,
    dekWrapAtlas: body.dekWrapAtlas,
    atlasSalt: body.atlasSalt,
    atlasVerify: body.atlasVerify,
    updatedAt: Date.now()
  };
  save(db);
  res.json({ ok: true });
});

app.get("/api/lock", (req, res) => {
  const key = req.query.userKey || "default";
  const db = load();
  res.json(db.locks[key] || null);
});

app.post("/api/items", (req, res) => {
  const b = req.body || {};
  if (!b.id || !b.deviceId || !b.ciphertext || !b.iv) {
    return res.status(400).json({ error: "id, deviceId, iv, ciphertext required" });
  }
  const key = b.userKey || "default";
  const db = load();
  if (!db.devices[key]) db.devices[key] = {};
  db.devices[key][b.deviceId] = {
    deviceId: b.deviceId,
    name: b.deviceName || b.deviceId,
    updatedAt: Date.now()
  };
  const row = {
    id: b.id,
    userKey: key,
    deviceId: b.deviceId,
    section: b.section === "normal" ? "normal" : "hide",
    mediaType: b.mediaType === "video" ? "video" : "photo",
    filename: b.filename || "file",
    mime: b.mime || "application/octet-stream",
    byteSize: b.byteSize || 0,
    iv: b.iv,
    ciphertext: b.ciphertext,
    thumb: b.thumb || null,
    createdAt: Date.now()
  };
  const idx = db.items.findIndex((x) => x.id === row.id);
  if (idx >= 0) db.items[idx] = row;
  else db.items.push(row);
  save(db);
  res.json({ ok: true, id: row.id });
});

app.get("/api/items", (req, res) => {
  const key = req.query.userKey || "default";
  const deviceId = req.query.deviceId;
  const section = req.query.section;
  const mediaType = req.query.mediaType;
  const db = load();
  let list = db.items.filter((x) => x.userKey === key);
  if (deviceId) list = list.filter((x) => x.deviceId === deviceId);
  if (section) list = list.filter((x) => x.section === section);
  if (mediaType) list = list.filter((x) => x.mediaType === mediaType);
  list.sort((a, b) => (b.createdAt || 0) - (a.updatedAt || 0));
  res.json(list);
});

app.delete("/api/items/:id", (req, res) => {
  const db = load();
  const before = db.items.length;
  db.items = db.items.filter((x) => x.id !== req.params.id);
  save(db);
  res.json({ ok: true, removed: before - db.items.length });
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log("Natural Beauty backend on :" + port);
});
