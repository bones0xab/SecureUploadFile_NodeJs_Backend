// init_db.js
const sqlite3 = require('sqlite3');
const { join, dirname } = require('path');
// Database file path
const dbFile = join(__dirname, 'metadata.db');

// Open (or create) the database
const db = new sqlite3.Database(dbFile, err => {
  if (err) {
    console.error('Cannot open database:', err);
    process.exit(1);
  }
  console.log('Connected to metadata.db');
});

// Create a simple 'files' table to store upload info
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS files (
       id           INTEGER PRIMARY KEY AUTOINCREMENT,
       fileName     TEXT    NOT NULL,
       fileType     TEXT,
       iv           BLOB    NOT NULL,
       salt         BLOB    NOT NULL,
       encPath      TEXT    NOT NULL,
       fileSize     INTEGER NOT NULL,
       passwordHash TEXT    NOT NULL,
       lastModified TEXT    NOT NULL,
       downloadToken TEXT   UNIQUE,
       tokenExpiry  INTEGER NOT NULL,
       download     INTEGER
     )`
  );
  console.log('✅ files table is ready');
});

module.exports = db;