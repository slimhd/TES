#!/usr/bin/env node
const crypto = require('crypto');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

// Parse CLI args
const args = process.argv.slice(2);
function getArg(name) {
    const idx = args.indexOf(`--${name}`);
    return idx !== -1 && args[idx + 1] ? args[idx + 1] : null;
}

const role = getArg('role');
const username = getArg('username');
const password = getArg('password');

if (!role || !username || !password) {
    console.log('Usage: node createUser.js --role <officer|police> --username <username> --password <password>');
    process.exit(1);
}

if (role !== 'officer' && role !== 'police') {
    console.log('Role must be "officer" or "police"');
    process.exit(1);
}

// Initialize DB
const dbDir = path.join(__dirname, '..', 'db');
const dbPath = path.join(dbDir, 'tes.db');

// Ensure db directory exists
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath);

// Run init.sql first
const initSql = fs.readFileSync(path.join(dbDir, 'init.sql'), 'utf-8');
db.exec(initSql, (err) => {
    if (err) {
        console.error('Error initializing database:', err);
        process.exit(1);
    }

    // Generate salt and hash password
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, derived) => {
        if (err) {
            console.error('Error hashing password:', err);
            process.exit(1);
        }

        const passHash = derived.toString('hex');

        db.run(
            'INSERT INTO users (username, pass_hash, salt, role) VALUES (?, ?, ?, ?)',
            [username, passHash, salt, role],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        console.error(`User "${username}" already exists.`);
                    } else {
                        console.error('Error creating user:', err);
                    }
                    process.exit(1);
                }
                console.log(`User created successfully!`);
                console.log(`  Username: ${username}`);
                console.log(`  Role: ${role}`);
                console.log(`  ID: ${this.lastID}`);
                db.close();
            }
        );
    });
});

