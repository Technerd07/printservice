'use strict';

require('dotenv').config();
const path = require('path');
const fs = require('fs').promises;
const { mkdirSync, existsSync, createWriteStream } = require('fs');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const multer = require('multer');
const crypto = require('crypto');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { Worker } = require('worker_threads');
const os = require('os');

// ==========================================
// Configuration & Security Constants
// ==========================================

const APP_PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const NODE_ENV = process.env.NODE_ENV || 'development';
const BASE_UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || '/home/whoami/Desktop/projects/xerofast/printservice/var/uploads');
const LOG_DIR = path.resolve(process.env.LOG_DIR || '/home/whoami/Desktop/projects/xerofast/printservice/var/logs');
const MAX_FILES = 5;
const MAX_FILE_BYTES = parseInt(process.env.MAX_FILE_BYTES || String(10 * 1024 * 1024), 10);
const REQUEST_ID_LENGTH = 16;
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

// Worker thread configuration
const MAX_WORKERS = parseInt(process.env.MAX_WORKERS || String(os.cpus().length), 10);

// NGINX configuration
const NGINX_PORT = 8080;
const NGINX_URL = process.env.NGINX_URL || `http://localhost:${NGINX_PORT}`;

// Session configuration
const SESSION_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours

// ==========================================
// Logging System
// ==========================================

class Logger {
  constructor(logDir) {
    this.logDir = logDir;
    this.streams = {};
    this.initLogDirectory();
  }

  initLogDirectory() {
    if (!existsSync(this.logDir)) {
      mkdirSync(this.logDir, { recursive: true, mode: 0o755 });
      console.log(`✓ Created log directory: ${this.logDir}`);
    }

    // Create log files
    const logTypes = ['access', 'error', 'audit', 'encryption', 'performance'];
    logTypes.forEach(type => {
      const logPath = path.join(this.logDir, `${type}.log`);
      this.streams[type] = createWriteStream(logPath, { flags: 'a' });
    });
  }

  formatLogEntry(level, category, message, metadata = {}) {
    return JSON.stringify({
      timestamp: new Date().toISOString(),
      level,
      category,
      message,
      ...metadata,
      pid: process.pid,
      hostname: os.hostname()
    }) + '\n';
  }

  write(type, level, category, message, metadata) {
    const entry = this.formatLogEntry(level, category, message, metadata);
    
    if (this.streams[type]) {
      this.streams[type].write(entry);
    }
    
    // Also log to console in development
    if (NODE_ENV === 'development') {
      console.log(`[${level}] ${category}: ${message}`);
    }
  }

  access(message, metadata) {
    this.write('access', 'INFO', 'ACCESS', message, metadata);
  }

  error(message, metadata) {
    this.write('error', 'ERROR', 'ERROR', message, metadata);
    console.error(`[ERROR] ${message}`, metadata);
  }

  audit(action, metadata) {
    this.write('audit', 'AUDIT', action, 'Audit trail', metadata);
  }

  encryption(message, metadata) {
    this.write('encryption', 'INFO', 'ENCRYPTION', message, metadata);
  }

  performance(operation, duration, metadata) {
    this.write('performance', 'PERF', operation, `Completed in ${duration}ms`, {
      duration,
      ...metadata
    });
  }

  close() {
    Object.values(this.streams).forEach(stream => stream.end());
  }
}

const logger = new Logger(LOG_DIR);

// ==========================================
// Worker Thread Pool Management
// ==========================================

class WorkerPool {
  constructor(maxWorkers, workerScript) {
    this.maxWorkers = maxWorkers;
    this.workerScript = workerScript;
    this.workers = [];
    this.queue = [];
    this.activeJobs = new Map();
    
    logger.audit('WORKER_POOL_INIT', {
      maxWorkers,
      cpuCount: os.cpus().length
    });
  }

  async initialize() {
    for (let i = 0; i < this.maxWorkers; i++) {
      this.workers.push({
        id: i,
        busy: false,
        worker: null
      });
    }
    logger.audit('WORKER_POOL_READY', { workers: this.maxWorkers });
  }

  async executeJob(jobData) {
    return new Promise((resolve, reject) => {
      const job = { jobData, resolve, reject, timestamp: Date.now() };
      
      const worker = this.getAvailableWorker();
      if (worker) {
        this.runJob(worker, job);
      } else {
        this.queue.push(job);
        logger.performance('QUEUE_JOB', 0, {
          queueSize: this.queue.length,
          jobId: jobData.jobId
        });
      }
    });
  }

  getAvailableWorker() {
    return this.workers.find(w => !w.busy);
  }

  runJob(workerSlot, job) {
    workerSlot.busy = true;
    const startTime = Date.now();

    const worker = new Worker(this.workerScript, {
      workerData: job.jobData
    });

    workerSlot.worker = worker;
    this.activeJobs.set(worker.threadId, job);

    worker.on('message', (result) => {
      const duration = Date.now() - startTime;
      logger.performance('WORKER_JOB_COMPLETE', duration, {
        jobId: job.jobData.jobId,
        threadId: worker.threadId
      });
      
      job.resolve(result);
      this.cleanupWorker(workerSlot, worker);
    });

    worker.on('error', (error) => {
      logger.error('WORKER_ERROR', {
        jobId: job.jobData.jobId,
        error: error.message,
        stack: error.stack
      });
      
      job.reject(error);
      this.cleanupWorker(workerSlot, worker);
    });

    worker.on('exit', (code) => {
      if (code !== 0) {
        logger.error('WORKER_EXIT_ERROR', {
          code,
          jobId: job.jobData.jobId
        });
      }
    });
  }

  cleanupWorker(workerSlot, worker) {
    workerSlot.busy = false;
    workerSlot.worker = null;
    this.activeJobs.delete(worker.threadId);

    // Process next job in queue
    if (this.queue.length > 0) {
      const nextJob = this.queue.shift();
      this.runJob(workerSlot, nextJob);
    }
  }

  getStats() {
    return {
      maxWorkers: this.maxWorkers,
      busyWorkers: this.workers.filter(w => w.busy).length,
      queueSize: this.queue.length,
      activeJobs: this.activeJobs.size
    };
  }
}

// Note: Worker pool structure ready but not used yet
// To enable: create encryption-worker.js and uncomment below
// const workerPool = new WorkerPool(MAX_WORKERS, path.join(__dirname, 'encryption-worker.js'));

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
      logger.error('INVALID_MASTER_KEY', { source: 'environment' });
      console.error('❌ MASTER_KEY provided but invalid. Exiting.');
      process.exit(1);
    }
  }
  logger.audit('MASTER_KEY_LOADED', { source: 'environment' });
  console.log('✓ MASTER_KEY loaded from environment');
} else {
  console.warn('⚠️  No MASTER_KEY provided. Running in development mode with ephemeral key.');
  console.warn('⚠️  This key will be lost on restart. Do NOT use in production.');
  MASTER_KEY = crypto.randomBytes(KEY_LENGTH);
  logger.audit('EPHEMERAL_KEY_GENERATED', { warning: 'development_only' });
}

if (!existsSync(BASE_UPLOAD_DIR)) {
  mkdirSync(BASE_UPLOAD_DIR, { recursive: true, mode: 0o700 });
  logger.audit('UPLOAD_DIR_CREATED', { path: BASE_UPLOAD_DIR });
  console.log(`✓ Created secure upload directory: ${BASE_UPLOAD_DIR}`);
}

// ==========================================
// Session Management System
// ==========================================

const sessions = new Map();

function createSession(jobId, clientIp) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + SESSION_EXPIRY;
  
  sessions.set(sessionId, {
    jobId: jobId,
    clientIp: clientIp,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt
  });
  
  // Cleanup old sessions
  cleanupExpiredSessions();
  
  logger.audit('SESSION_CREATED', {
    sessionId: sessionId.slice(0, 8) + '...',
    jobId: jobId,
    clientIp: clientIp
  });
  
  return sessionId;
}

function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;
  
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    logger.audit('SESSION_EXPIRED_AUTO', { sessionId: sessionId.slice(0, 8) + '...' });
    return null;
  }
  
  // Extend session on valid access
  session.expiresAt = Date.now() + SESSION_EXPIRY;
  return session;
}

function cleanupExpiredSessions() {
  const now = Date.now();
  let cleaned = 0;
  
  for (const [sessionId, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(sessionId);
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    logger.audit('SESSION_CLEANUP', { cleanedCount: cleaned });
  }
}

// Cleanup every hour
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

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
  const startTime = Date.now();
  
  if (!key || key.length !== KEY_LENGTH) {
    throw new Error('Invalid encryption key length');
  }

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  const hash = computeHash(buffer);

  const duration = Date.now() - startTime;
  logger.encryption('FILE_ENCRYPTED', {
    originalSize: buffer.length,
    encryptedSize: encrypted.length,
    duration
  });

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

  logger.encryption('KEY_WRAPPED', { keyLength: fileKey.length });
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

  logger.encryption('KEY_UNWRAPPED', { keyLength: key.length });
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
  const startTime = Date.now();
  
  try {
    const stat = await fs.stat(filePath);
    const size = stat.size;

    for (let i = 0; i < passes; i++) {
      await fs.writeFile(filePath, crypto.randomBytes(size));
    }

    await fs.writeFile(filePath, Buffer.alloc(size, 0));
    await fs.unlink(filePath);
    
    const duration = Date.now() - startTime;
    logger.audit('SECURE_DELETE', {
      filePath: path.basename(filePath),
      size,
      passes,
      duration
    });
  } catch (err) {
    logger.error('SECURE_DELETE_FAILED', {
      filePath: path.basename(filePath),
      error: err.message
    });
    
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

function getClientIp(req) {
  if (!req || !req.headers) return 'UNKNOWN_IP';
  return req.headers['x-real-ip'] || 
         (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : null) || 
         req.ip || 
         'UNKNOWN_IP';
}

// ==========================================
// Express App Setup
// ==========================================

const app = express();

// Trust proxy headers from Nginx
app.set('trust proxy', true);

// CORS configuration
app.use(cors({
  origin: NGINX_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'Cookie']
}));

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginOpenerPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  noSniff: true,
  xssFilter: true
}));

// Custom morgan format with file logging
morgan.token('real-ip', (req) => getClientIp(req));
morgan.token('request-id', (req) => req.id || 'NO_ID');

const accessLogStream = createWriteStream(path.join(LOG_DIR, 'http-access.log'), { flags: 'a' });

app.use(morgan(':real-ip :method :url :status :res[content-length] - :response-time ms [:request-id]', {
  skip: (req) => req.path === '/health',
  stream: accessLogStream
}));

app.use(morgan(':real-ip :method :url :status :res[content-length] - :response-time ms [:request-id]', {
  skip: (req) => req.path === '/health'
}));

// Request ID middleware with logging
app.use((req, res, next) => {
  req.id = generateRequestId();
  req.startTime = Date.now();
  res.setHeader('X-Request-ID', req.id);
  
  logger.access('REQUEST_RECEIVED', {
    requestId: req.id,
    method: req.method,
    path: req.path,
    ip: getClientIp(req),
    userAgent: req.headers['user-agent']
  });
  
  // Log response
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    logger.access('REQUEST_COMPLETED', {
      requestId: req.id,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration
    });
  });
  
  next();
});

// Body parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Cookie parsing
app.use(cookieParser());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  validate:false,
  skip: (req) => req.path === '/health',
  handler: (req, res) => {
    logger.audit('RATE_LIMIT_EXCEEDED', {
      ip: getClientIp(req),
      path: req.path,
      requestId: req.id
    });
    res.status(429).json({
      error: 'Too many requests, please try again later.',
      retryAfter: '60 seconds'
    });
  }
});
app.use('/api/', apiLimiter);

// Upload-specific rate limiter
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  validate:false,
  handler: (req, res) => {
    logger.audit('UPLOAD_RATE_LIMIT_EXCEEDED', {
      ip: getClientIp(req),
      requestId: req.id
    });
    res.status(429).json({
      error: 'Too many upload requests. Please try again later.',
      retryAfter: '15 minutes'
    });
  }
});

// Multer configuration
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
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'image/jpeg',
      'image/png',
      'image/gif',
      'text/plain',
      'application/rtf'
    ];

    if (!allowed.includes(file.mimetype)) {
      logger.audit('FILE_TYPE_REJECTED', {
        filename: file.originalname,
        mimetype: file.mimetype,
        ip: getClientIp(req)
      });
      return cb(new Error(`Unsupported file type: ${file.mimetype}`));
    }

    if (!file.originalname || file.originalname.length > 260) {
      return cb(new Error('Invalid filename length'));
    }

    if (file.originalname.includes('\0')) {
      logger.audit('NULL_BYTE_ATTACK_DETECTED', {
        filename: file.originalname,
        ip: getClientIp(req)
      });
      return cb(new Error('Filename contains null bytes'));
    }

    cb(null, true);
  }
});

// ==========================================
// Routes
// ==========================================

app.get('/health', (req, res) => {
  const uptime = process.uptime();
  const memUsage = process.memoryUsage();
  
  res.json({
    status: 'ok',
    service: 'PrintEase Encryption API',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    nodeVersion: process.version,
    uptime: Math.floor(uptime),
    memory: {
      rss: formatBytes(memUsage.rss),
      heapUsed: formatBytes(memUsage.heapUsed),
      heapTotal: formatBytes(memUsage.heapTotal)
    }
  });
});

app.get('/api', (req, res) => {
  res.json({
    service: 'PrintEase Secure Encryption API',
    version: '1.0.0',
    endpoints: {
      upload: 'POST /api/upload',
      myOrder: 'GET /api/my-order',
      listJobs: 'GET /api/jobs',
      getJob: 'GET /api/jobs/:id',
      deleteJob: 'DELETE /api/jobs/:id',
      stats: 'GET /api/stats',
      health: 'GET /health'
    },
    encryption: {
      algorithm: ENCRYPTION_ALGORITHM,
      keyLength: KEY_LENGTH * 8,
      maxFileSize: formatBytes(MAX_FILE_BYTES),
      maxFiles: MAX_FILES
    }
  });
});

// Stats endpoint
app.get('/api/stats', async (req, res) => {
  try {
    const uptime = process.uptime();
    const memUsage = process.memoryUsage();
    
    // Count total jobs
    const jobDirs = await fs.readdir(BASE_UPLOAD_DIR, { withFileTypes: true });
    const totalJobs = jobDirs.filter(d => d.isDirectory()).length;
    
    res.json({
      system: {
        uptime: Math.floor(uptime),
        memory: {
          rss: formatBytes(memUsage.rss),
          heapUsed: formatBytes(memUsage.heapUsed),
          heapTotal: formatBytes(memUsage.heapTotal)
        },
        cpu: os.cpus().length,
        platform: os.platform(),
        nodeVersion: process.version
      },
      jobs: {
        total: totalJobs
      },
      sessions: {
        active: sessions.size
      },
      config: {
        maxWorkers: MAX_WORKERS,
        maxFileSize: formatBytes(MAX_FILE_BYTES),
        maxFiles: MAX_FILES
      }
    });
  } catch (err) {
    logger.error('STATS_ERROR', { error: err.message });
    res.status(500).json({ error: 'Failed to retrieve stats' });
  }
});

// Secure file upload with session creation
app.post('/api/upload', uploadLimiter, upload.array('files', MAX_FILES), async (req, res, next) => {
  const requestId = req.id;
  const startTime = Date.now();
  const clientIp = getClientIp(req);

  try {
    if (!req.files || req.files.length === 0) {
      logger.audit('UPLOAD_NO_FILES', { requestId, ip: clientIp });
      return res.status(400).json({ 
        error: 'No files provided',
        code: 'NO_FILES'
      });
    }

    logger.audit('UPLOAD_START', {
      requestId,
      ip: clientIp,
      fileCount: req.files.length,
      totalSize: req.files.reduce((sum, f) => sum + f.size, 0)
    });

    const jobId = generateJobId();
    const jobDir = path.join(BASE_UPLOAD_DIR, jobId);

    await fs.mkdir(jobDir, { recursive: true, mode: 0o700 });

    const meta = {
      jobId,
      createdAt: new Date().toISOString(),
      clientInfo: {
        ip: clientIp,
        userAgent: req.headers['user-agent'] || 'Unknown'
      },
      encryption: {
        algorithm: ENCRYPTION_ALGORITHM,
        keyLength: KEY_LENGTH * 8,
        ivLength: IV_LENGTH * 8,
        tagLength: AUTH_TAG_LENGTH * 8
      },
      files: []
    };

    for (const file of req.files) {
      const fileStartTime = Date.now();
      
      logger.encryption('ENCRYPTING_FILE', {
        requestId,
        jobId,
        filename: file.originalname,
        size: file.size
      });

      const fileKey = crypto.randomBytes(KEY_LENGTH);
      const { encrypted, iv, tag, hash } = encryptBufferAESGCM(file.buffer, fileKey);
      const { wrapped, iv: wrapIv, tag: wrapTag } = wrapKey(fileKey);

      const safeName = sanitizeFilename(file.originalname);
      const encFilename = `${safeName}.enc`;
      const encPath = path.join(jobDir, encFilename);

      await safeWriteFile(encPath, encrypted, 0o600);

      const fileDuration = Date.now() - fileStartTime;
      
      logger.performance('FILE_ENCRYPTED', fileDuration, {
        requestId,
        jobId,
        filename: file.originalname,
        originalSize: file.size,
        encryptedSize: encrypted.length
      });

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
        wrapTag: wrapTag.toString('base64'),
        uploadedAt: new Date().toISOString()
      });
    }

    const metaPath = path.join(jobDir, 'meta.json');
    await safeWriteFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)), 0o600);

    // Create secure session instead of exposing jobId
    const sessionId = createSession(jobId, clientIp);

    // Set secure HttpOnly cookie (inaccessible to JavaScript)
    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: SESSION_EXPIRY,
      path: '/'
    });

    const duration = Date.now() - startTime;
    
    logger.audit('UPLOAD_SUCCESS', {
      requestId,
      jobId,
      ip: clientIp,
      fileCount: meta.files.length,
      duration,
      sessionCreated: true
    });
    
    logger.performance('UPLOAD_COMPLETE', duration, {
      requestId,
      jobId,
      fileCount: meta.files.length
    });

    // Return success WITHOUT jobId
    return res.status(201).json({ 
      success: true, 
      message: `Successfully encrypted ${meta.files.length} file(s)`,
      fileCount: meta.files.length,
      processingTime: `${duration}ms`
    });

  } catch (err) {
    logger.error('UPLOAD_FAILED', {
      requestId,
      ip: clientIp,
      error: err.message,
      stack: err.stack
    });
    next(err);
  }
});

// Get user's current order via session
app.get('/api/my-order', async (req, res, next) => {
  const requestId = req.id;
  const clientIp = getClientIp(req);
  
  try {
    // Get session from secure HttpOnly cookie
    const sessionId = req.cookies.sessionId;
    
    if (!sessionId) {
      logger.audit('NO_SESSION_ORDER_PAGE', { requestId, ip: clientIp });
      return res.status(401).json({ 
        error: 'No active session. Please upload files first.',
        code: 'NO_SESSION'
      });
    }
    
    // Validate session
    const session = getSession(sessionId);
    if (!session) {
      logger.audit('INVALID_SESSION_ORDER_PAGE', { 
        requestId, 
        ip: clientIp,
        sessionId: sessionId.slice(0, 8) + '...'
      });
      
      // Clear invalid cookie
      res.clearCookie('sessionId');
      return res.status(401).json({ 
        error: 'Session expired. Please upload files again.',
        code: 'SESSION_EXPIRED'
      });
    }
    
    // Get job details using server-controlled jobId
    const jobId = session.jobId;
    const metaPath = path.join(BASE_UPLOAD_DIR, jobId, 'meta.json');
    
    if (!isPathSafe(BASE_UPLOAD_DIR, metaPath)) {
      logger.error('PATH_SAFETY_CHECK_FAILED', { requestId, jobId });
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    const raw = await fs.readFile(metaPath, 'utf8');
    const meta = JSON.parse(raw);
    
    // Return order details WITHOUT exposing jobId
    const orderDetails = {
      createdAt: meta.createdAt,
      fileCount: meta.files.length,
      files: meta.files.map(f => ({
        originalName: f.originalName,
        mimetype: f.mimetype,
        originalSize: f.originalSize,
        encryptedSize: f.encryptedSize,
        uploadedAt: f.uploadedAt
      })),
      encryption: meta.encryption
    };
    
    logger.audit('ORDER_DETAILS_RETRIEVED', {
      requestId,
      jobId,
      ip: clientIp,
      fileCount: orderDetails.fileCount
    });
    
    res.json({ 
      success: true,
      order: orderDetails 
    });
    
  } catch (err) {
    if (err.code === 'ENOENT') {
      logger.audit('ORDER_JOB_NOT_FOUND', { requestId });
      return res.status(404).json({ 
        error: 'Order not found or has been deleted.',
        code: 'ORDER_NOT_FOUND'
      });
    }
    logger.error('GET_ORDER_ERROR', {
      requestId,
      error: err.message
    });
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

    logger.audit('JOBS_LISTED', { requestId, count: jobs.length });
    res.json({ jobs });

  } catch (err) {
    logger.error('LIST_JOBS_ERROR', {
      requestId,
      error: err.message
    });
    next(err);
  }
});

app.get('/api/jobs/:id', async (req, res, next) => {
  const requestId = req.id;
  const jobId = String(req.params.id);

  try {
    if (!isValidJobId(jobId)) {
      logger.audit('INVALID_JOB_ID', { requestId, jobId });
      return res.status(400).json({ error: 'Invalid job ID' });
    }

    const metaPath = path.join(BASE_UPLOAD_DIR, jobId, 'meta.json');

    if (!isPathSafe(BASE_UPLOAD_DIR, metaPath)) {
      logger.audit('PATH_TRAVERSAL_ATTEMPT', {
        requestId,
        jobId,
        ip: getClientIp(req)
      });
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

    logger.audit('JOB_RETRIEVED', { requestId, jobId });
    res.json({ job: safeMeta });

  } catch (err) {
    if (err.code === 'ENOENT') {
      logger.audit('JOB_NOT_FOUND', { requestId, jobId });
      return res.status(404).json({ error: 'Job not found' });
    }
    logger.error('GET_JOB_ERROR', {
      requestId,
      jobId,
      error: err.message
    });
    next(err);
  }
});

app.delete('/api/jobs/:id', async (req, res, next) => {
  const requestId = req.id;
  const jobId = String(req.params.id);
  const clientIp = getClientIp(req);

  try {
    if (!isValidJobId(jobId)) {
      logger.audit('INVALID_JOB_ID_DELETE', { requestId, jobId, ip: clientIp });
      return res.status(400).json({ error: 'Invalid job ID' });
    }

    const jobDir = path.join(BASE_UPLOAD_DIR, jobId);

    if (!isPathSafe(BASE_UPLOAD_DIR, jobDir)) {
      logger.audit('PATH_TRAVERSAL_DELETE_ATTEMPT', {
        requestId,
        jobId,
        ip: clientIp
      });
      return res.status(400).json({ error: 'Invalid job path' });
    }

    const files = await fs.readdir(jobDir);
    for (const file of files) {
      const filePath = path.join(jobDir, file);
      await secureDelete(filePath);
    }

    await fs.rmdir(jobDir);

    logger.audit('JOB_DELETED', {
      requestId,
      jobId,
      ip: clientIp,
      fileCount: files.length
    });

    res.json({ success: true, deleted: jobId });

  } catch (err) {
    if (err.code === 'ENOENT') {
      logger.audit('DELETE_JOB_NOT_FOUND', { requestId, jobId });
      return res.status(404).json({ error: 'Job not found' });
    }
    logger.error('DELETE_JOB_ERROR', {
      requestId,
      jobId,
      error: err.message
    });
    next(err);
  }
});

app.get('/api/download/:id', async (req, res, next) => {
  const jobId = req.params.id;
  const requestId = req.id;
  
  if (!isValidJobId(jobId)) {
    logger.audit('INVALID_DOWNLOAD_JOB_ID', { requestId, jobId });
    return res.status(400).json({ error: 'Invalid job ID' });
  }

  try {
    const metaPath = path.join(BASE_UPLOAD_DIR, jobId, 'meta.json');
    const raw = await fs.readFile(metaPath, 'utf8');
    const meta = JSON.parse(raw);
    
    logger.audit('DOWNLOAD_INFO_REQUESTED', {
      requestId,
      jobId,
      ip: getClientIp(req)
    });
    
    res.json({
      jobId,
      files: meta.files.map(f => ({
        originalName: f.originalName,
        downloadUrl: `${NGINX_URL}/api/download/${jobId}/${f.encFilename}`
      }))
    });
    
  } catch (err) {
    if (err.code === 'ENOENT') {
      logger.audit('DOWNLOAD_JOB_NOT_FOUND', { requestId, jobId });
      return res.status(404).json({ error: 'Job not found' });
    }
    next(err);
  }
});

// ==========================================
// Error Handlers
// ==========================================

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    let statusCode = 400;
    let message = 'Upload error';
    let code = 'UPLOAD_ERROR';

    if (err.code === 'LIMIT_FILE_SIZE') {
      message = `File too large (max ${formatBytes(MAX_FILE_BYTES)})`;
      code = 'FILE_TOO_LARGE';
    } else if (err.code === 'LIMIT_FILE_COUNT') {
      message = `Too many files (max ${MAX_FILES})`;
      code = 'TOO_MANY_FILES';
    }

    logger.error('MULTER_ERROR', {
      requestId: req?.id,
      code: err.code,
      ip: getClientIp(req)
    });

    return res.status(statusCode).json({ 
      error: message,
      code,
      maxFileSize: MAX_FILE_BYTES,
      maxFiles: MAX_FILES
    });
  }

  if (err && err.message) {
    logger.error('VALIDATION_ERROR', {
      requestId: req?.id,
      error: err.message,
      ip: getClientIp(req)
    });
    
    return res.status(400).json({ 
      error: err.message,
      code: 'VALIDATION_ERROR'
    });
  }

  next(err);
});

app.use((err, req, res, next) => {
  const requestId = req?.id || 'NO_REQUEST_ID';
  const clientIp = getClientIp(req);
  
  logger.error('UNHANDLED_ERROR', {
    requestId,
    ip: clientIp,
    error: err?.message || 'Unknown error',
    stack: err?.stack
  });

  const statusCode = err?.statusCode || 500;
  const isDev = NODE_ENV === 'development';

  const response = {
    error: 'Internal server error',
    requestId,
    timestamp: new Date().toISOString()
  };

  if (isDev && err) {
    response.details = err.message;
    if (err.stack) response.stack = err.stack;
  }

  res.status(statusCode).json(response);
});

// 404 Handler
app.use('*', (req, res) => {
  logger.audit('ROUTE_NOT_FOUND', {
    path: req.originalUrl,
    method: req.method,
    ip: getClientIp(req)
  });
  
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// ==========================================
// Server Startup
// ==========================================

const server = app.listen(APP_PORT, HOST, () => {
  logger.audit('SERVER_STARTED', {
    port: APP_PORT,
    host: HOST,
    environment: NODE_ENV,
    uploadDir: BASE_UPLOAD_DIR,
    logDir: LOG_DIR,
    sessionExpiry: `${SESSION_EXPIRY / (60 * 60 * 1000)} hours`
  });

  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║           PrintEase Encryption API (SECURE)                 ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');
  console.log(`  🔒 API Server: http://${HOST}:${APP_PORT}`);
  console.log(`  🌐 Nginx Proxy: ${NGINX_URL}`);
  console.log(`  📁 Upload Dir: ${BASE_UPLOAD_DIR}`);
  console.log(`  📋 Log Dir: ${LOG_DIR}`);
  console.log(`  🔐 Encryption: ${ENCRYPTION_ALGORITHM.toUpperCase()}`);
  console.log(`  🛡️  Session Security: HttpOnly cookies enabled`);
  console.log(`  📄 Max File Size: ${formatBytes(MAX_FILE_BYTES)}`);
  console.log(`  📦 Max Files: ${MAX_FILES}`);
  console.log(`  ⚡ Environment: ${NODE_ENV}`);
  console.log(`  🔄 Trust Proxy: ${app.get('trust proxy')}`);
  console.log(`  💻 Workers: ${MAX_WORKERS} (CPU cores: ${os.cpus().length})`);
  console.log('\n  ✅ SECURE server started successfully\n');
});

// Graceful shutdown
function gracefulShutdown(signal) {
  console.log(`\n\n✓ Received ${signal}. Shutting down gracefully...`);
  
  logger.audit('SERVER_SHUTDOWN', { 
    signal,
    activeSessions: sessions.size,
    activeJobs: Object.keys(require('worker_threads').threadId || {}).length
  });
  
  server.close(() => {
    console.log('✓ Node.js server closed');
    logger.close();
    process.exit(0);
  });

  setTimeout(() => {
    console.error('❌ Forced shutdown due to timeout');
    logger.audit('FORCED_SHUTDOWN', { signal });
    logger.close();
    process.exit(1);
  }, 10000);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

process.on('uncaughtException', (err) => {
  logger.error('UNCAUGHT_EXCEPTION', {
    error: err.message,
    stack: err.stack
  });
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('UNHANDLED_REJECTION', {
    reason: reason?.message || reason,
    stack: reason?.stack
  });
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

module.exports = app;
