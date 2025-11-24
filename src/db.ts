import Database from "better-sqlite3";
import path from "path";
import fs from "fs";

const dbPath = path.join(__dirname, "..", "data");
if (!fs.existsSync(dbPath)) {
  fs.mkdirSync(dbPath, { recursive: true });
}

const dbFile = path.join(dbPath, "app.sqlite");

const db = new Database(dbFile);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    secret_message TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

export default db;
