-- Users table (officer and police)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('officer', 'police'))
);

-- Drivers table
CREATE TABLE IF NOT EXISTS drivers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plate TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL
);

-- Violations table (stored as DES-encrypted messages)
CREATE TABLE IF NOT EXISTS violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plate TEXT NOT NULL,
    speed INTEGER NOT NULL,
    points INTEGER NOT NULL,
    stored_ciphertext_b64 TEXT NOT NULL,
    iv_b64 TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

