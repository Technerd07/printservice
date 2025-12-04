'use strict';

require('dotenv').config();
const path = require('path');
const fs = require('fs').promises;
const { mkdirSync, existsSync } = require('fs');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const multer = require('multer');
const crypto = require('crypto');

// ==========================================
// Configuration & Security Constants
// ==========================================

const APP_PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const BASE_UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, '..', 'var', 'uploads'));
const MAX_FILES = 5;
const MAX_FILE_BYTES = parseInt(process.env.MAX_FILE_BYTES || String(10 * 1024 * 1024), 10);
const REQUEST_ID_LENGTH = 16;
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

// ==========================================
// Master Key Management
// ==========================================

let MASTER_KEY;

if (process.env.MASTER_KEY) {
  try {
    MASTER_KEY = Buffer.from(process.env.MASTER_KEY, 'base64');
    if (MASTER_KEY.length !== KEY_LENGTH) throw new Error('bad length');
  } catch {
    try {
      MASTER_KEY = Buffer.from(process.env.MASTER_KEY, 'hex');
      if (MASTER_KEY.length !== KEY_LENGTH) throw new Error('bad length');
    } catch {
      console.error('❌ MASTER_KEY provided but invalid. Exiting.');
      process.exit(1);
    }
  }
  console.log('✓ MASTER_KEY loaded from environment');
} else {
  console.warn('⚠️  No MASTER_KEY provided. Running in development mode with ephemeral key.');
  console.warn('⚠️  This key will be lost on restart. Do NOT use in production.');
  MASTER_KEY = crypto.randomBytes(KEY_LENGTH);
}

if (!existsSync(BASE_UPLOAD_DIR)) {
  mkdirSync(BASE_UPLOAD_DIR, { recursive: true, mode: 0o700 });
  console.log(`✓ Created secure upload directory: ${BASE_UPLOAD_DIR}`);
}

// ==========================================
// Utility Functions
// ==========================================

function generateRequestId() {
  return crypto.randomBytes(REQUEST_ID_LENGTH).toString('hex');
}

function generateJobId() {
  return crypto.randomBytes(16).toString('hex');
}

function sanitizeFilename(name = '') {
  const base = path.basename(name).replace(/\0/g, '');
  const cleaned = base.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 200);
  return cleaned || 'file';
}

function computeHash(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

function encryptBufferAESGCM(buffer, key) {
  if (!key || key.length !== KEY_LENGTH) {
    throw new Error('Invalid encryption key length');
  }

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  const hash = computeHash(buffer);

  return { encrypted, iv, tag, hash };
}

function decryptBufferAESGCM(encrypted, key, iv, tag) {
  if (!key || key.length !== KEY_LENGTH) {
    throw new Error('Invalid decryption key length');
  }

  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(tag);
  
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

function wrapKey(fileKey) {
  if (!fileKey || fileKey.length !== KEY_LENGTH) {
    throw new Error('Invalid file key length');
  }

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, MASTER_KEY, iv, { authTagLength: AUTH_TAG_LENGTH });
  
  const wrapped = Buffer.concat([cipher.update(fileKey), cipher.final()]);
  const tag = cipher.getAuthTag();

  return { wrapped, iv, tag };
}

function unwrapKey(wrapped, iv, tag) {
  if (!wrapped || !iv || !tag) {
    throw new Error('Missing unwrap parameters');
  }

  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, MASTER_KEY, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(tag);
  
  const key = Buffer.concat([decipher.update(wrapped), decipher.final()]);
  if (key.length !== KEY_LENGTH) {
    throw new Error('Unwrapped key has invalid length');
  }

  return key;
}

async function safeWriteFile(filePath, data, mode = 0o600) {
  const tmp = `${filePath}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  
  try {
    await fs.writeFile(tmp, data, { mode });
    await fs.rename(tmp, filePath);
    await fs.chmod(filePath, mode);
  } catch (err) {
    try {
      await fs.unlink(tmp);
    } catch {
      // ignore
    }
    throw err;
  }
}

async function secureDelete(filePath, passes = 3) {
  try {
    const stat = await fs.stat(filePath);
    const size = stat.size;

    for (let i = 0; i < passes; i++) {
      await fs.writeFile(filePath, crypto.randomBytes(size));
    }

    await fs.writeFile(filePath, Buffer.alloc(size, 0));
    await fs.unlink(filePath);
  } catch (err) {
    console.error(`Error securely deleting ${filePath}:`, err);
    try {
      await fs.unlink(filePath);
    } catch {
      // ignore
    }
  }
}

function isValidJobId(id) {
  return typeof id === 'string' && /^[a-f0-9]{32}$/.test(id);
}

function isPathSafe(basePath, targetPath) {
  const resolved = path.resolve(targetPath);
  const base = path.resolve(basePath);
  return resolved.startsWith(base + path.sep) || resolved === base;
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

// ==========================================
// Express App Setup
// ==========================================

const app = express();

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  hsts: { maxAge: 31536000, includeSubDomains: true }
}));

app.use(morgan(':remote-addr :method :url :status :res[content-length] - :response-time ms', {
  skip: (req) => req.path === '/health'
}));

app.use((req, res, next) => {
  req.id = generateRequestId();
  res.setHeader('X-Request-ID', req.id);
  next();
});

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Serve frontend static files (no custom keyGenerator — removed IPv6 error)
app.use(express.static(path.resolve(__dirname, '../frontend')));

// Global API rate limiter (FIXED: removed custom keyGenerator)
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', apiLimiter);

// Upload-specific rate limiter (FIXED: removed custom keyGenerator)
const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: MAX_FILE_BYTES,
    files: MAX_FILES,
    parts: MAX_FILES + 10
  },
  fileFilter: (req, file, cb) => {
    const allowed = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Unsupported file type'));
    }

    if (!file.originalname || file.originalname.length > 260) {
      return cb(new Error('Invalid filename'));
    }

    if (file.originalname.includes('\0')) {
      return cb(new Error('Filename contains null bytes'));
    }

    cb(null, true);
  }
});

// ==========================================
// Routes
// ==========================================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.post('/api/upload', uploadLimiter, upload.array('files', MAX_FILES), async (req, res, next) => {
  const requestId = req.id;
  const startTime = Date.now();

  try {
    if (!req.files || req.files.length === 0) {
      console.warn(`[${requestId}] Upload rejected: no files provided`);
      return res.status(400).json({ error: 'No files provided' });
    }

    console.log(`[${requestId}] Processing ${req.files.length} file(s)`);

    const jobId = generateJobId();
    const jobDir = path.join(BASE_UPLOAD_DIR, jobId);

    await fs.mkdir(jobDir, { recursive: true, mode: 0o700 });

    const meta = {
      jobId,
      createdAt: new Date().toISOString(),
      encryption: {
        algorithm: ENCRYPTION_ALGORITHM,
        keyLength: KEY_LENGTH * 8,
        ivLength: IV_LENGTH * 8,
        tagLength: AUTH_TAG_LENGTH * 8
      },
      files: []
    };

    for (const file of req.files) {
      console.log(`[${requestId}] Encrypting: ${file.originalname} (${file.size} bytes)`);

      const fileKey = crypto.randomBytes(KEY_LENGTH);
      const { encrypted, iv, tag, hash } = encryptBufferAESGCM(file.buffer, fileKey);
      const { wrapped, iv: wrapIv, tag: wrapTag } = wrapKey(fileKey);

      const safeName = sanitizeFilename(file.originalname);
      const encFilename = `${safeName}.enc`;
      const encPath = path.join(jobDir, encFilename);

      await safeWriteFile(encPath, encrypted, 0o600);

      meta.files.push({
        originalName: file.originalname,
        safeName,
        encFilename,
        mimetype: file.mimetype,
        originalSize: file.size,
        encryptedSize: encrypted.length,
        iv: iv.toString('base64'),
        authTag: tag.toString('base64'),
        hash: hash.toString('base64'),
        wrappedKey: wrapped.toString('base64'),
        wrapIv: wrapIv.toString('base64'),
        wrapTag: wrapTag.toString('base64')
      });
    }

    const metaPath = path.join(jobDir, 'meta.json');
    await safeWriteFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)), 0o600);

    const safeMeta = {
      jobId: meta.jobId,
      createdAt: meta.createdAt,
      encryption: meta.encryption,
      files: meta.files.map(f => ({
        originalName: f.originalName,
        encFilename: f.encFilename,
        mimetype: f.mimetype,
        originalSize: f.originalSize,
        encryptedSize: f.encryptedSize
      }))
    };

    const duration = Date.now() - startTime;
    console.log(`[${requestId}] ✓ Job ${jobId} created in ${duration}ms`);

    return res.status(201).json({ success: true, job: safeMeta });

  } catch (err) {
    console.error(`[${requestId}] Error:`, err);
    next(err);
  }
});

app.get('/api/jobs', async (req, res, next) => {
  const requestId = req.id;

  try {
    const ids = await fs.readdir(BASE_UPLOAD_DIR, { withFileTypes: true });
    const jobs = [];

    for (const d of ids) {
      if (!d.isDirectory()) continue;

      const metaPath = path.join(BASE_UPLOAD_DIR, d.name, 'meta.json');
      try {
        const raw = await fs.readFile(metaPath, 'utf8');
        const meta = JSON.parse(raw);

        jobs.push({
          jobId: meta.jobId,
          createdAt: meta.createdAt,
          fileCount: meta.files.length
        });
      } catch {
        // Skip unreadable entries
      }
    }

    console.log(`[${requestId}] Returned ${jobs.length} job(s)`);
    res.json({ jobs });

  } catch (err) {
    console.error(`[${requestId}] Error listing jobs:`, err);
    next(err);
  }
});

app.get('/api/jobs/:id', async (req, res, next) => {
  const requestId = req.id;
  const jobId = String(req.params.id);

  try {
    if (!isValidJobId(jobId)) {
      console.warn(`[${requestId}] Invalid job ID format: ${jobId}`);
      return res.status(400).json({ error: 'Invalid job ID' });
    }

    const metaPath = path.join(BASE_UPLOAD_DIR, jobId, 'meta.json');

    if (!isPathSafe(BASE_UPLOAD_DIR, metaPath)) {
      console.warn(`[${requestId}] Path traversal attempt detected`);
      return res.status(400).json({ error: 'Invalid job path' });
    }

    const raw = await fs.readFile(metaPath, 'utf8');
    const meta = JSON.parse(raw);

    const safeMeta = {
      jobId: meta.jobId,
      createdAt: meta.createdAt,
      encryption: meta.encryption,
      files: meta.files.map(f => ({
        originalName: f.originalName,
        encFilename: f.encFilename,
        mimetype: f.mimetype,
        originalSize: f.originalSize,
        encryptedSize: f.encryptedSize
      }))
    };

    console.log(`[${requestId}] Retrieved job ${jobId}`);
    res.json({ job: safeMeta });

  } catch (err) {
    if (err.code === 'ENOENT') {
      console.warn(`[${requestId}] Job not found: ${jobId}`);
      return res.status(404).json({ error: 'Job not found' });
    }
    console.error(`[${requestId}] Error retrieving job:`, err);
    next(err);
  }
});

app.delete('/api/jobs/:id', async (req, res, next) => {
  const requestId = req.id;
  const jobId = String(req.params.id);

  try {
    if (!isValidJobId(jobId)) {
      console.warn(`[${requestId}] Invalid job ID for deletion: ${jobId}`);
      return res.status(400).json({ error: 'Invalid job ID' });
    }

    const jobDir = path.join(BASE_UPLOAD_DIR, jobId);

    if (!isPathSafe(BASE_UPLOAD_DIR, jobDir)) {
      console.warn(`[${requestId}] Path traversal attempt in deletion`);
      return res.status(400).json({ error: 'Invalid job path' });
    }

    const files = await fs.readdir(jobDir);
    for (const file of files) {
      const filePath = path.join(jobDir, file);
      await secureDelete(filePath);
    }

    await fs.rmdir(jobDir);

    console.log(`[${requestId}] ✓ Job ${jobId} securely deleted`);
    res.json({ success: true, deleted: jobId });

  } catch (err) {
    if (err.code === 'ENOENT') {
      console.warn(`[${requestId}] Job not found for deletion: ${jobId}`);
      return res.status(404).json({ error: 'Job not found' });
    }
    console.error(`[${requestId}] Error deleting job:`, err);
    next(err);
  }
});

// SPA fallback (optional)
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.resolve(__dirname, '../frontend/encryptionDashboard.html'));
});

// ==========================================
// Error Handlers
// ==========================================

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    let statusCode = 400;
    let message = 'Upload error';

    if (err.code === 'LIMIT_FILE_SIZE') {
      message = `File too large (max ${formatBytes(MAX_FILE_BYTES)})`;
    } else if (err.code === 'LIMIT_FILE_COUNT') {
      message = `Too many files (max ${MAX_FILES})`;
    }

    console.error(`[${req.id}] Multer error: ${err.code}`);
    return res.status(statusCode).json({ error: message });
  }

  if (err && err.message) {
    return res.status(400).json({ error: err.message });
  }

  next(err);
});

app.use((err, req, res) => {
  console.error(`[${req.id}] Unhandled error:`, err && err.stack ? err.stack : err);

  const statusCode = err.statusCode || 500;
  const isDev = process.env.NODE_ENV === 'development';

  res.status(statusCode).json({
    error: 'Internal server error',
    ...(isDev && { details: err.message })
  });
});

// ==========================================
// Server Startup & Shutdown
// ==========================================

const server = app.listen(APP_PORT, HOST, () => {
  console.log('\n╔═════════════════════════════════════════╗');
  console.log('║   PrintEase Encryption Server Ready    ║');
  console.log('╚═════════════════════════════════════════╝\n');
  console.log(`  Host: ${HOST}`);
  console.log(`  Port: ${APP_PORT}`);
  console.log(`  URL: http://${HOST}:${APP_PORT}`);
  console.log(`  Upload Dir: ${BASE_UPLOAD_DIR}`);
  console.log(`  Encryption: ${ENCRYPTION_ALGORITHM.toUpperCase()}`);
  console.log(`  Max File Size: ${formatBytes(MAX_FILE_BYTES)}`);
  console.log(`  Max Files: ${MAX_FILES}`);
  console.log('\n  Ready for secure uploads...\n');
});

function gracefulShutdown(signal) {
  console.log(`\n\n✓ Received ${signal}. Shutting down gracefully...`);
  
  server.close(() => {
    console.log('✓ Server closed');
    process.exit(0);
  });

  setTimeout(() => {
    console.error('❌ Forced shutdown due to timeout');
    process.exit(1);
  }, 10000);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

module.exports = app;