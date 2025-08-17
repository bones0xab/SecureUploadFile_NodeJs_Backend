const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const db = require('../init_db.js');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { throwError } = require('rxjs');
const { type } = require('os');
const { error } = require('console');



router.post('/upload', async (req, res) => {
  try {
    const { cipher, iv, salt, fileName, fileType, fileSize, lastModified, password, downloadCount,expiredTime } = req.body;
    if (!cipher || !iv || !salt || !fileName || !password) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    // decode base64
    const cipherBuf = Buffer.from(cipher, 'base64');
    const ivBuf = Buffer.from(iv, 'base64');
    const saltBuf = Buffer.from(salt, 'base64');
    const passwordHash = await bcrypt.hash(password, 10)

   
    // ensure uploads dir
    const uploadDir = path.join(process.cwd(), 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

    // Save encrypted file
    const encPath = path.join(uploadDir, `${fileName}.enc`);
    await fs.promises.writeFile(encPath, cipherBuf);


    // Token 
    const token = crypto.randomBytes(32).toString('hex');

    
    // Insert metadata into DB
    try {
      db.run(
        `INSERT INTO files (fileName, fileType, iv, salt, encPath, fileSize, passwordHash, lastModified, downloadToken, tokenExpiry, download)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [fileName, fileType, ivBuf, saltBuf, encPath, fileSize , passwordHash, lastModified, token, expiredTime, downloadCount],
        function(err) {
          if (err) {
            console.error('DB insert failed:', err);
            return res.status(500).json({ error: 'DB insert failed' });
          }
          const link = `${req.protocol}://${req.get('host')}/download/${token}`;
          res.json({ id: this.lastID, token, link , expiredTime : new Date(expiredTime).toISOString() });
        }
      );  
    } catch (error) {
      console.log(error)
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// router.get('/download/:token', (req, res) => {

//   const token = req.params.token;
 
//   db.get(`SELECT salt, iv, encPath, tokenExpiry, fileName, fileType  FROM files WHERE downloadToken = ?`,
//    [token],
//     (err, row) => {
//    if(err) {
//     console.err('DB error',err);
//     return res.status(500).json({err: 'server Error '});
//    }

//    if(!row) return res.status(404).json({
//     err: 'Not Found'
//    });

//    if(Date.now() > row.tokenExpiry){
//     res.status(410).json({error : 'Link Expired'})
//    }

//    const filePath = row.encPath;

//    if(!filePath || !fs.existsSync(filePath)){
//     console.error('File Missing On disk',filePath)
//     return res.status(404).json({error: 'File Missing'});
//    }

//    const ivB64 = row.iv ? Buffer.from(row.iv).toString('base64') : null;
//     const saltB64 = row.salt ? Buffer.from(row.salt).toString('base64') : null;

//       if (ivB64) res.setHeader('x-iv', ivB64);
//       if (saltB64) res.setHeader('x-salt', saltB64);

//       // file metadata headers
//       if (row.fileName) res.setHeader('x-file-name', row.fileName);
//       if (row.fileType) res.setHeader('x-file-type', row.fileType);
//       res.setHeader('Content-Type', 'application/octet-stream');
//       res.setHeader('Access-Control-Expose-Headers', 'x-iv, x-salt, x-file-name, x-file-type');

//       // do not set Content-Disposition to original name unless you want browser to download encrypted file with .enc
//       // e.g. res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filePath)}"`);

//       const stream = fs.createReadStream(filePath);
//       stream.on('error', (streamErr) => {
//         console.error('File stream error', streamErr);
//         if (!res.headersSent) res.status(500).end('File stream error');
//         else res.destroy(streamErr);
//       });
//       stream.pipe(res);
//   })

//   });

router.post('/download', async (req, res) => {
  try {
    // Prefer header token; fall back to param if you want backward compatibility
    const authHeader = req.headers['authorization'] || '';
    const headerToken = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    const token = headerToken || req.params.token;

    const password = req.body?.password;
    if (!token || !password) return res.status(400).json({ error: 'Missing token or password' });

    db.get(`SELECT salt, iv, encPath, tokenExpiry, fileName, fileType, passwordHash, downloadToken, download FROM files WHERE downloadToken = ?`,
      [token],
      async (err, row) => {
        if (err) {
          console.error('DB error', err);
          return res.status(500).json({ err: 'Server error' });
        }
        if (!row) return res.status(404).json({ err: 'Not Found' });
        if (Date.now() > row.tokenExpiry) 
        {
          db.run(`DELETE FROM files WHERE downloadToken = ?`, [token]);
          return res.status(410).json({ error: 'Link Expired' });
        }
        if (row.download <= 0) {
          db.run(`DELETE FROM files WHERE downloadToken = ?`, [token]);
          return res.status(410).json({error :'No download file !'})
        }
        // Verify password (stored as hash) - use bcrypt
        
        const match = await bcrypt.compare(password, row.passwordHash);
        if (!match) return res.status(401).json({ error: 'Invalid password' });

        const filePath = row.encPath;
        if (!filePath || !fs.existsSync(filePath)) return res.status(404).json({ error: 'File missing' });

        // Send iv/salt as base64 headers for client to derive key
        const ivB64 = row.iv ? Buffer.from(row.iv).toString('base64') : null;
        const saltB64 = row.salt ? Buffer.from(row.salt).toString('base64') : null;
        if (ivB64) res.setHeader('x-iv', ivB64);
        if (saltB64) res.setHeader('x-salt', saltB64);

        if (row.fileName) res.setHeader('x-file-name', row.fileName);
        if (row.fileType) res.setHeader('x-file-type', row.fileType); // MIME like application/pdf

        // Expose headers to browser
        res.setHeader('Access-Control-Expose-Headers', 'x-iv, x-salt, x-file-name, x-file-type');

        // Stream encrypted file (client will decrypt)
        // Decrement download count before streaming
db.run(
  `UPDATE files SET download = download - 1 WHERE downloadToken = ? AND download > 0`,
  [token],
  function (updateErr) {
    if (updateErr) {
      console.error('DB update error', updateErr);
      return res.status(500).json({ error: 'Failed to update download count' });
    }

    if (this.changes === 0) {
      // Means no row updated (downloads already 0)
      return res.status(410).json({ error: 'No download left!' });
    }

    // Stream encrypted file (client will decrypt)
    const stream = fs.createReadStream(filePath);
    stream.on('error', (streamErr) => {
      console.error('File stream error', streamErr);
      if (!res.headersSent) res.status(500).end('File stream error');
      else res.destroy(streamErr);
    });

    res.setHeader('Content-Type', 'application/octet-stream');
    stream.pipe(res);
  }
);

      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});
  

  module.exports = router;