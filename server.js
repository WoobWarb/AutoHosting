const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const AdmZip = require('adm-zip');
const slugify = require('slugify');
const cors = require('cors');
const { exec } = require('child_process');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.set('trust proxy', 1); // behind Nginx — needed for req.secure to reflect the real protocol
const PORT = process.env.PORT || 3000;

// Google OAuth verification (Client ID is public info; the secret is never used server-side)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '555675730734-h761tbt5a5ivu1c41agdi8h3v23ffr4o.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Verify a Google ID token and return the authenticated user, or null if invalid
async function verifyGoogleToken(idToken) {
  if (!idToken) return null;
  try {
    const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload || !payload.email) return null;
    return {
      email: payload.email,
      name: payload.name || payload.email.split('@')[0],
      picture: payload.picture || '',
      googleId: payload.sub
    };
  } catch (e) {
    return null;
  }
}

// ---------------- ID/Pass local credentials (no Google required) ----------------
// users.json lives next to server.js (gitignored). Each entry:
// { "woob": { name, salt, hash (scrypt hex), admin } }
const PASS_USERS_FILE = path.join(__dirname, 'users.json');
let PASS_USERS = {};
try { PASS_USERS = JSON.parse(fs.readFileSync(PASS_USERS_FILE, 'utf8')); } catch (e) {}

function hashPass(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function savePassUsers() {
  fs.writeFileSync(PASS_USERS_FILE, JSON.stringify(PASS_USERS, null, 2));
}
function verifyPassCredentials(id, password) {
  const rec = PASS_USERS[String(id).toLowerCase()];
  if (!rec || !rec.salt || !rec.hash || !password) return null;
  const candidate = Buffer.from(hashPass(password, rec.salt));
  const stored = Buffer.from(rec.hash);
  if (candidate.length !== stored.length || !crypto.timingSafeEqual(candidate, stored)) return null;
  return { email: 'pass:' + String(id).toLowerCase(), name: rec.name || id, passUser: true, admin: !!rec.admin };
}

// CLI: node server.js --add-user <id> <password> [--admin]
if (require.main === module && process.argv[2] === '--add-user') {
  const uid = process.argv[3]; const pwd = process.argv[4]; const wantAdmin = process.argv[5] === '--admin';
  if (!uid || !pwd) { console.error('Usage: node server.js --add-user <id> <password> [--admin]'); process.exit(1); }
  const key = uid.toLowerCase();
  const salt = crypto.randomBytes(16).toString('hex');
  const prevAdmin = (PASS_USERS[key] && PASS_USERS[key].admin) || false;
  PASS_USERS[key] = { name: uid, salt, hash: hashPass(pwd, salt), admin: wantAdmin || prevAdmin };
  savePassUsers();
  console.log('PASS user "' + uid + '" saved' + (PASS_USERS[key].admin ? ' (admin)' : ''));
  process.exit(0);
}

// Verify a signed session token (same format as the nct_session cookie: id|expiry|sig).
// Lets API calls carry the ID/Pass session via Authorization: Bearer <token>.
function verifySessionToken(raw) {
  if (!raw) return null;
  try {
    const parts = String(raw).split('|');
    const id = parts[0], expiry = parts[1], sig = parts[2];
    if (!id || !expiry || !sig) return null;
    if (Date.now() > parseInt(expiry, 10)) return null;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(id + '|' + expiry).digest('hex');
    const sigBuf = Buffer.from(sig); const expBuf = Buffer.from(expected);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
    return id;
  } catch (e) { return null; }
}

// Middleware: require a valid Google ID token in the Authorization header.
// Attaches the server-verified identity to req.authUser — never trust a client-supplied email.
// Also accepts ID/Pass session tokens (signed with SESSION_SECRET) as Bearer tokens.
async function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  let user = idToken ? await verifyGoogleToken(idToken) : null;
  if (!user && idToken) {
    const idPart = verifySessionToken(idToken);
    if (idPart && idPart.startsWith('pass:')) {
      const rec = PASS_USERS[idPart.slice(5)];
      if (rec) user = { email: idPart, name: rec.name || idPart.slice(5), passUser: true, admin: !!rec.admin };
    }
  }
  if (!user) {
    return res.status(401).json({ success: false, message: 'Authentication required. Please sign in (Google or ID/Pass).' });
  }
  req.authUser = user;
  next();
}

// Middleware: like requireAuth, but doesn't reject the request when no/invalid token is
// present — just leaves req.authUser unset. Used by endpoints that are public but should
// still know who's asking (e.g. to include the requester's own private projects).
async function softAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  let user = idToken ? await verifyGoogleToken(idToken) : null;
  if (!user && idToken) {
    const idPart = verifySessionToken(idToken);
    if (idPart && idPart.startsWith('pass:')) {
      const rec = PASS_USERS[idPart.slice(5)];
      if (rec) user = { email: idPart, name: rec.name || idPart.slice(5), passUser: true, admin: !!rec.admin };
    }
  }
  req.authUser = user;
  next();
}

// Admins can see and manage every project regardless of visibility or ownership
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '0deathwolf@gmail.com')
  .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
function isAdmin(email) {
  if (!email) return false;
  if (ADMIN_EMAILS.includes(email.toLowerCase())) return true;
  if (email.startsWith('pass:')) {
    const rec = PASS_USERS[email.slice(5)];
    return !!(rec && rec.admin);
  }
  return false;
}

// Session cookie: lets a plain browser page-navigation (which can't carry an Authorization
// header) prove who's asking, so "self" visibility can actually be enforced on the raw
// hosted URL, not just on API calls.
const SESSION_SECRET_FILE = path.join(__dirname, '.session_secret');
let SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  if (fs.existsSync(SESSION_SECRET_FILE)) {
    SESSION_SECRET = fs.readFileSync(SESSION_SECRET_FILE, 'utf8').trim();
  } else {
    SESSION_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(SESSION_SECRET_FILE, SESSION_SECRET);
  }
}

function parseCookies(cookieHeader) {
  const out = {};
  (cookieHeader || '').split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) { try { out[k] = decodeURIComponent(v); } catch (e) { out[k] = v; } }
  });
  return out;
}

function getSessionEmail(req) {
  try {
    const raw = parseCookies(req.headers.cookie)['nct_session'];
    if (!raw) return null;
    const [email, expiry, sig] = raw.split('|');
    if (!email || !expiry || !sig) return null;
    if (Date.now() > parseInt(expiry, 10)) return null;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(`${email}|${expiry}`).digest('hex');
    const sigBuf = Buffer.from(sig);
    const expBuf = Buffer.from(expected);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
    return email;
  } catch (e) {
    return null;
  }
}



// API: Establish a session cookie after Google sign-in (needed so page navigation to a
// "self"-visibility project URL can be recognized as coming from the owner/admin)
app.post('/api/session/login', requireAuth, (req, res) => {
  const email = req.authUser.email;
  const expiry = Date.now() + 12 * 60 * 60 * 1000; // 12h
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(`${email}|${expiry}`).digest('hex');
  res.cookie('nct_session', `${email}|${expiry}|${sig}`, {
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    sameSite: 'lax',
    maxAge: 12 * 60 * 60 * 1000
  });
  res.json({ success: true });
});

app.post('/api/session/logout', (req, res) => {
  res.clearCookie('nct_session');
  res.json({ success: true });
});

// API: GitHub Auto Deploy Webhook (verified via HMAC signature, see README_DEPLOY.md)
const DEPLOY_WEBHOOK_SECRET = process.env.DEPLOY_WEBHOOK_SECRET || '';

app.post('/api/webhook/deploy', express.raw({ type: '*/*', limit: '5mb' }), (req, res) => {
  if (!DEPLOY_WEBHOOK_SECRET) {
    console.error('Webhook rejected: DEPLOY_WEBHOOK_SECRET is not configured on the server.');
    return res.status(503).json({ success: false, message: 'Webhook not configured.' });
  }

  const signature = req.headers['x-hub-signature-256'] || '';
  const expectedSignature = 'sha256=' + crypto.createHmac('sha256', DEPLOY_WEBHOOK_SECRET).update(req.body || Buffer.alloc(0)).digest('hex');

  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expectedSignature);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    console.warn('Webhook rejected: invalid or missing signature.');
    return res.status(401).json({ success: false, message: 'Invalid signature.' });
  }

  console.log('🔄 Webhook received: Pulling latest changes from GitHub...');

  exec('git pull origin main && npm install --production && pm2 restart html-uploader', { cwd: __dirname }, (error, stdout, stderr) => {
    if (error) {
      console.error(`Auto Deploy Error: ${error.message}`);
      return res.status(500).json({ success: false, message: error.message, stderr });
    }
    console.log(`Auto Deploy Success: ${stdout}`);
    return res.json({ success: true, message: 'Deployed successfully!', stdout });
  });
});

// Directories
const PROJECTS_DIR = path.join(__dirname, 'projects');
const TEMP_DIR = path.join(__dirname, 'temp_uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Ensure required directories exist
[PROJECTS_DIR, TEMP_DIR, PUBLIC_DIR].forEach((dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// API: Login with local ID/Pass credentials — sets the same nct_session cookie and
// returns a signed session token for use as Authorization: Bearer on API calls.
app.post('/api/pass/login', (req, res) => {
  const id = String((req.body && req.body.id) || '').trim();
  const password = String((req.body && req.body.password) || '');
  if (!id || !password) return res.status(400).json({ success: false, message: 'ID and password are required.' });
  const user = verifyPassCredentials(id, password);
  if (!user) return res.status(401).json({ success: false, message: 'ID or password is incorrect.' });
  const idPart = 'pass:' + id.toLowerCase();
  const expiry = Date.now() + 12 * 60 * 60 * 1000; // 12h
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(idPart + '|' + expiry).digest('hex');
  const token = idPart + '|' + expiry + '|' + sig;
  res.cookie('nct_session', token, {
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    sameSite: 'lax',
    maxAge: 12 * 60 * 60 * 1000
  });
  res.json({ success: true, token, name: user.name });
});

app.use(express.urlencoded({ extended: true }));

// Middleware to prevent browser caching of dashboard HTML
app.use((req, res, next) => {
  if (req.path === '/' || req.path === '/index.html') {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

// Serve main Dashboard UI
app.use(express.static(PUBLIC_DIR));

// Note: hosted projects (/projects/<slug> and /<slug>) are served further down by a
// visibility-gated handler, not a blanket express.static mount — see resolveProjectRequest.

// Configure Multer for temp file storage
const upload = multer({
  dest: TEMP_DIR,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB max
});

// Helper: Clean up slug
function cleanSlug(input) {
  return slugify(input || '', {
    lower: true,
    strict: true,
    trim: true
  }) || 'project';
}

// Helper: Best-effort short summary pulled from the page itself, used when no description was typed
function extractAutoDescription(htmlContent) {
  try {
    const metaMatch = htmlContent.match(/<meta[^>]+name=["']description["'][^>]*content=["']([^"']*)["']/i)
      || htmlContent.match(/<meta[^>]+content=["']([^"']*)["'][^>]*name=["']description["']/i);
    if (metaMatch && metaMatch[1].trim()) {
      return metaMatch[1].trim().slice(0, 200);
    }

    const titleMatch = htmlContent.match(/<title[^>]*>([^<]*)<\/title>/i);
    const title = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : '';

    const bodyMatch = htmlContent.match(/<body[^>]*>([\s\S]*)<\/body>/i);
    const text = (bodyMatch ? bodyMatch[1] : htmlContent)
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/\s+/g, ' ')
      .trim();

    if (title && text) {
      const snippet = text.slice(0, 140).trim();
      return snippet ? `${title} — ${snippet}${text.length > 140 ? '...' : ''}` : title;
    }
    if (title) return title;
    if (text) return text.slice(0, 160).trim() + (text.length > 160 ? '...' : '');
    return '';
  } catch (e) {
    return '';
  }
}

// Helper: Ensure unique slug directory name
function getUniqueSlug(baseSlug) {
  let slug = baseSlug;
  let counter = 1;
  while (fs.existsSync(path.join(PROJECTS_DIR, slug))) {
    slug = `${baseSlug}-${counter}`;
    counter++;
  }
  return slug;
}

// Helper: Recursively calculate directory size & file count
function getFolderStats(dirPath) {
  let totalSize = 0;
  let fileCount = 0;

  function scan(currentPath) {
    if (!fs.existsSync(currentPath)) return;
    const items = fs.readdirSync(currentPath);
    for (const item of items) {
      // Skip version-history snapshots when reporting a project's live size
      if (item === '.versions') continue;
      const fullPath = path.join(currentPath, item);
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        scan(fullPath);
      } else {
        totalSize += stat.size;
        fileCount++;
      }
    }
  }

  scan(dirPath);
  return { totalSize, fileCount };
}

// Spaces Registry Helper
const SPACES_FILE = path.join(PROJECTS_DIR, '_spaces.json');
function getStoredSpaces() {
  if (fs.existsSync(SPACES_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(SPACES_FILE, 'utf8'));
      if (Array.isArray(data) && data.length > 0) return data;
    } catch(e) {}
  }
  return ['General'];
}

function saveStoredSpaces(spaces) {
  try {
    fs.writeFileSync(SPACES_FILE, JSON.stringify(spaces, null, 2));
  } catch(e) {}
}

// API: Get Spaces with Project Counts
app.get('/api/spaces', (req, res) => {
  try {
    const storedSpaces = getStoredSpaces();
    const spaceSet = new Set(storedSpaces);
    
    // Count projects per space
    const counts = {};
    storedSpaces.forEach(s => counts[s] = 0);

    const entries = fs.readdirSync(PROJECTS_DIR, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const metaPath = path.join(PROJECTS_DIR, entry.name, '.metadata.json');
        if (fs.existsSync(metaPath)) {
          try {
            const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
            const sp = meta.space || 'General';
            spaceSet.add(sp);
            counts[sp] = (counts[sp] || 0) + 1;
          } catch(e) {}
        }
      }
    }

    const spacesList = Array.from(spaceSet).map(name => ({
      name,
      count: counts[name] || 0
    }));

    res.json({ success: true, spaces: spacesList });
  } catch(err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// API: Create New Space
app.post('/api/spaces', (req, res) => {
  try {
    const rawName = (req.body.name || '').trim();
    if (!rawName) {
      return res.status(400).json({ success: false, message: 'Space name cannot be empty.' });
    }
    const spaces = getStoredSpaces();
    if (!spaces.includes(rawName)) {
      spaces.push(rawName);
      saveStoredSpaces(spaces);
    }
    res.json({ success: true, message: `Space '${rawName}' created successfully.`, spaces });
  } catch(err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// API: Delete Space
app.delete('/api/spaces/:name', (req, res) => {
  try {
    const target = req.params.name;
    if (target === 'General') {
      return res.status(400).json({ success: false, message: 'Cannot delete default General space.' });
    }
    let spaces = getStoredSpaces().filter(s => s !== target);
    if (spaces.length === 0) spaces = ['General'];
    saveStoredSpaces(spaces);

    // Reassign projects from deleted space to 'General'
    const entries = fs.readdirSync(PROJECTS_DIR, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const metaPath = path.join(PROJECTS_DIR, entry.name, '.metadata.json');
        if (fs.existsSync(metaPath)) {
          try {
            const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
            if (meta.space === target) {
              meta.space = 'General';
              fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2));
            }
          } catch(e) {}
        }
      }
    }

    res.json({ success: true, message: `Space '${target}' removed. Projects moved to General.` });
  } catch(err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// API: Get List of Deployed Projects
app.get('/api/projects', softAuth, (req, res) => {
  try {
    const requesterEmail = req.authUser ? req.authUser.email.toLowerCase() : null;
    const requesterIsAdmin = isAdmin(requesterEmail);

    const entries = fs.readdirSync(PROJECTS_DIR, { withFileTypes: true });
    const allProjects = [];
    const authorSet = new Set();
    let totalSizeBytes = 0;

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (entry.name.startsWith('.')) continue; // skip hidden dirs like .versions
        const slug = entry.name;
        const projectPath = path.join(PROJECTS_DIR, slug);
        const metaPath = path.join(projectPath, '.metadata.json');

        let metadata = {};
        if (fs.existsSync(metaPath)) {
          try {
            metadata = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
          } catch (e) {}
        }

        const stats = getFolderStats(projectPath);
        const dirStat = fs.statSync(projectPath);

        // Check entry points
        const hasIndexHtml = fs.existsSync(path.join(projectPath, 'index.html'));
        let mainFile = 'index.html';
        if (!hasIndexHtml) {
          const files = fs.readdirSync(projectPath).filter(f => f.endsWith('.html'));
          if (files.length > 0) mainFile = files[0];
        }

        const author = metadata.author || { name: 'Anonymous', email: '', picture: '' };
        const archived = !!metadata.archived;

        // "Active" totals exclude archived projects, but still reflect every owner's
        // project regardless of visibility — always the true count, not a filtered one
        if (!archived) {
          totalSizeBytes += stats.totalSize;
          authorSet.add(author.email || author.name || 'Anonymous');
        }

        allProjects.push({
          slug,
          title: metadata.title || slug,
          description: metadata.description || 'No description provided.',
          author,
          space: metadata.space || 'General',
          visibility: metadata.visibility || 'public',
          archived,
          viewsCount: metadata.viewsCount || 0,
          url: `/${slug}/${hasIndexHtml ? '' : mainFile}`,
          directUrl: `/${slug}`,
          createdAt: metadata.createdAt || dirStat.birthtime || dirStat.mtime,
          updatedAt: metadata.updatedAt || metadata.createdAt || dirStat.mtime,
          originalFileName: metadata.originalFileName || 'N/A',
          fileType: metadata.fileType || 'html',
          fileCount: stats.fileCount,
          sizeBytes: stats.totalSize,
          mainFile
        });
      }
    }

    // Private/self projects are hidden from everyone except their owner and admins.
    // Archived projects are hidden from everyone except their owner and admins too
    // (who still see them, so they can restore them from an "Archived" view).
    const visibleProjects = allProjects.filter(p => {
      const isOwner = requesterEmail && p.author.email && p.author.email.toLowerCase() === requesterEmail;
      if (p.archived) return isOwner || requesterIsAdmin;
      if (p.visibility === 'public') return true;
      return isOwner || requesterIsAdmin;
    });

    // Sort newest first
    visibleProjects.sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt));

    res.json({
      success: true,
      projects: visibleProjects,
      stats: {
        totalProjects: allProjects.filter(p => !p.archived).length,
        totalSizeBytes,
        totalAuthors: authorSet.size
      }
    });
  } catch (err) {
    console.error('Error fetching projects:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// Storage Quota Settings (Adaptable for VPS Capacity)
const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;
const MAX_VERSIONS_PER_PROJECT = 20;

// Take a snapshot of a project's current live files into .versions/<timestamp>/ (returns snapshot dir or null if nothing to save)
function snapshotProjectFiles(targetPath) {
  try {
    const items = fs.readdirSync(targetPath).filter(n => !n.startsWith('.'));
    if (items.length === 0) return null;
    const versionsDir = path.join(targetPath, '.versions');
    fs.mkdirSync(versionsDir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const snapshotDir = path.join(versionsDir, stamp);
    for (const item of items) {
      fs.cpSync(path.join(targetPath, item), path.join(snapshotDir, item), { recursive: true });
    }
    // Prune oldest snapshots beyond the limit
    const existing = fs.readdirSync(versionsDir, { withFileTypes: true })
      .filter(e => e.isDirectory()).map(e => e.name).sort();
    while (existing.length > MAX_VERSIONS_PER_PROJECT) {
      fs.rmSync(path.join(versionsDir, existing.shift()), { recursive: true, force: true });
    }
    return snapshotDir;
  } catch (e) {
    console.error('Snapshot failed (non-fatal):', e.message);
    return null;
  }
}
const QUOTA_NCT_TEAM_BYTES = 500 * 1024 * 1024; // 500MB per NCT Team member (@nctprosperatech.com)
const QUOTA_PUBLIC_USER_BYTES = 200 * 1024 * 1024; // 200MB per Public User

// Helper: Calculate total storage used by a specific author email
function getUserTotalStorageBytes(userEmail) {
  if (!userEmail) return 0;
  let totalBytes = 0;
  try {
    const entries = fs.readdirSync(PROJECTS_DIR, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const metaPath = path.join(PROJECTS_DIR, entry.name, '.metadata.json');
        if (fs.existsSync(metaPath)) {
          try {
            const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
            if (meta.author && meta.author.email && meta.author.email.toLowerCase() === userEmail.toLowerCase()) {
              const stats = getFolderStats(path.join(PROJECTS_DIR, entry.name));
              totalBytes += stats.totalSize;
            }
          } catch(e) {}
        }
      }
    }
  } catch(e) {}
  return totalBytes;
}

// API: Upload HTML or ZIP
app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
  const tempFilePath = req.file ? req.file.path : null;

  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded.' });
    }

    // Check Single File Size Limit (50MB)
    if (req.file.size > MAX_FILE_SIZE_BYTES) {
      if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
      return res.status(400).json({
        success: false,
        message: `File size exceeds max limit of 50 MB. Your file size: ${(req.file.size / (1024 * 1024)).toFixed(1)} MB.`
      });
    }

    const originalName = req.file.originalname;
    const ext = path.extname(originalName).toLowerCase();
    const rawCustomSlug = req.body.slug;
    const rawCustomTitle = req.body.title;
    const description = (req.body.description || '').trim();
    const space = (req.body.space || 'General').trim();
    const VALID_VISIBILITY = ['public', 'private', 'self'];
    const visibility = VALID_VISIBILITY.includes(req.body.visibility) ? req.body.visibility : 'public';

    // Author identity comes from the server-verified Google token — email/googleId/picture can
    // never be overridden by the client. The display name is purely cosmetic, so we do let the
    // user override just that, capped to a sane length.
    const customDisplayName = (req.body.displayName || '').trim().slice(0, 60);
    const author = { ...req.authUser, name: customDisplayName || req.authUser.name };

    // Enforce Per-User Storage Quota
    const userEmail = author.email.toLowerCase();
    const isNctTeam = userEmail.endsWith('@nctprosperatech.com') || userEmail.startsWith('pass:');
    const userQuotaBytes = isNctTeam ? QUOTA_NCT_TEAM_BYTES : QUOTA_PUBLIC_USER_BYTES;
    const currentUsedBytes = getUserTotalStorageBytes(userEmail);

    if (currentUsedBytes + req.file.size > userQuotaBytes) {
      if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
      const usedMb = (currentUsedBytes / (1024 * 1024)).toFixed(1);
      const limitMb = (userQuotaBytes / (1024 * 1024)).toFixed(0);
      return res.status(400).json({
        success: false,
        message: `Storage quota limit reached (${usedMb} MB / ${limitMb} MB limit). Please delete old projects to free up disk space.`
      });
    }

    const baseSlug = cleanSlug(rawCustomSlug || path.basename(originalName, ext));
    const targetSlug = getUniqueSlug(baseSlug);
    const targetPath = path.join(PROJECTS_DIR, targetSlug);

    fs.mkdirSync(targetPath, { recursive: true });

    let fileType = 'html';

    if (ext === '.zip') {
      fileType = 'zip';
      const zip = new AdmZip(tempFilePath);
      zip.extractAllTo(targetPath, true);

      // Flatten subfolder if zip contained a single root directory
      const contents = fs.readdirSync(targetPath);
      if (contents.length === 1) {
        const singleSubfolder = path.join(targetPath, contents[0]);
        if (fs.statSync(singleSubfolder).isDirectory()) {
          const subContents = fs.readdirSync(singleSubfolder);
          for (const item of subContents) {
            fs.renameSync(path.join(singleSubfolder, item), path.join(targetPath, item));
          }
          fs.rmdirSync(singleSubfolder);
        }
      }
    } else if (ext === '.html' || ext === '.htm') {
      fileType = 'html';
      // Save as index.html so /<slug> works seamlessly
      const destPath = path.join(targetPath, 'index.html');
      fs.copyFileSync(tempFilePath, destPath);
    } else {
      if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
      return res.status(400).json({
        success: false,
        message: 'Unsupported file type. Please upload a .html file or a .zip package.'
      });
    }

    // Clean up temp upload file
    if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);

    // If no description was typed, try to pull a short summary from the page itself
    let finalDescription = description;
    if (!finalDescription) {
      try {
        let mainHtmlPath = path.join(targetPath, 'index.html');
        if (!fs.existsSync(mainHtmlPath)) {
          const htmlFiles = fs.readdirSync(targetPath).filter(f => f.toLowerCase().endsWith('.html'));
          if (htmlFiles.length > 0) mainHtmlPath = path.join(targetPath, htmlFiles[0]);
        }
        if (fs.existsSync(mainHtmlPath)) {
          finalDescription = extractAutoDescription(fs.readFileSync(mainHtmlPath, 'utf8'));
        }
      } catch (e) {}
    }

    // Save Metadata
    const stats = getFolderStats(targetPath);
    const metadata = {
      slug: targetSlug,
      title: rawCustomTitle ? rawCustomTitle.trim() : (rawCustomSlug ? rawCustomSlug.trim() : targetSlug),
      description: finalDescription || 'No description provided.',
      space: space || 'General',
      visibility,
      archived: false,
      viewsCount: 0,
      author: {
        name: author.name || 'Anonymous',
        email: author.email || '',
        picture: author.picture || '',
        googleId: author.googleId || ''
      },
      originalFileName: originalName,
      fileType,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      sizeBytes: stats.totalSize,
      fileCount: stats.fileCount
    };

    fs.writeFileSync(path.join(targetPath, '.metadata.json'), JSON.stringify(metadata, null, 2));

    const projectUrl = `/${targetSlug}/`;

    return res.json({
      success: true,
      message: 'Project uploaded and deployed successfully!',
      slug: targetSlug,
      url: projectUrl,
      project: {
        ...metadata,
        url: projectUrl
      }
    });

  } catch (err) {
    if (tempFilePath && fs.existsSync(tempFilePath)) {
      fs.unlinkSync(tempFilePath);
    }
    console.error('Upload Error:', err);
    return res.status(500).json({ success: false, message: 'Upload failed: ' + err.message });
  }
});

// API: Deploy from pasted HTML code — same pipeline as file upload (slug, visibility,
// quota, metadata, auto-description) but the source is raw code instead of a file
app.post('/api/upload-code', requireAuth, (req, res) => {
  try {
    const htmlContent = req.body && req.body.code ? String(req.body.code) : '';
    if (!htmlContent.trim()) {
      return res.status(400).json({ success: false, message: 'No HTML code provided.' });
    }

    // Same 50MB size ceiling as file uploads
    const codeBytes = Buffer.byteLength(htmlContent, 'utf8');
    if (codeBytes > MAX_FILE_SIZE_BYTES) {
      return res.status(400).json({
        success: false,
        message: `HTML code exceeds the 50 MB size limit. Your code size: ${(codeBytes / (1024 * 1024)).toFixed(1)} MB.`
      });
    }

    const rawCustomSlug = req.body.slug;
    const rawCustomTitle = req.body.title;
    const description = (req.body.description || '').trim();
    const space = (req.body.space || 'General').trim();
    const VALID_VISIBILITY = ['public', 'private', 'self'];
    const visibility = VALID_VISIBILITY.includes(req.body.visibility) ? req.body.visibility : 'public';

    // Author identity comes from the server-verified Google token — display name is the
    // only client-supplied field, capped to a sane length (same as file uploads)
    const customDisplayName = (req.body.displayName || '').trim().slice(0, 60);
    const author = { ...req.authUser, name: customDisplayName || req.authUser.name };

    // Enforce Per-User Storage Quota (same limits as file uploads)
    const userEmail = author.email.toLowerCase();
    const isNctTeam = userEmail.endsWith('@nctprosperatech.com') || userEmail.startsWith('pass:');
    const userQuotaBytes = isNctTeam ? QUOTA_NCT_TEAM_BYTES : QUOTA_PUBLIC_USER_BYTES;
    const currentUsedBytes = getUserTotalStorageBytes(userEmail);

    if (currentUsedBytes + codeBytes > userQuotaBytes) {
      const usedMb = (currentUsedBytes / (1024 * 1024)).toFixed(1);
      const limitMb = (userQuotaBytes / (1024 * 1024)).toFixed(0);
      return res.status(400).json({
        success: false,
        message: `Storage quota limit reached (${usedMb} MB / ${limitMb} MB limit). Please delete old projects to free up disk space.`
      });
    }

    const baseSlug = cleanSlug(rawCustomSlug || 'pasted-page');
    const targetSlug = getUniqueSlug(baseSlug);
    const targetPath = path.join(PROJECTS_DIR, targetSlug);
    fs.mkdirSync(targetPath, { recursive: true });

    // Save the pasted code as index.html so /<slug> works seamlessly
    fs.writeFileSync(path.join(targetPath, 'index.html'), htmlContent, 'utf8');

    // If no description was typed, try to pull a short summary from the page itself
    let finalDescription = description;
    if (!finalDescription) {
      finalDescription = extractAutoDescription(htmlContent);
    }

    const stats = getFolderStats(targetPath);
    const metadata = {
      slug: targetSlug,
      title: rawCustomTitle ? rawCustomTitle.trim() : (rawCustomSlug ? rawCustomSlug.trim() : targetSlug),
      description: finalDescription || 'No description provided.',
      space: space || 'General',
      visibility,
      archived: false,
      viewsCount: 0,
      author: {
        name: author.name || 'Anonymous',
        email: author.email || '',
        picture: author.picture || '',
        googleId: author.googleId || ''
      },
      originalFileName: '(pasted code)',
      fileType: 'html',
      source: 'pasted',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      sizeBytes: stats.totalSize,
      fileCount: stats.fileCount
    };

    fs.writeFileSync(path.join(targetPath, '.metadata.json'), JSON.stringify(metadata, null, 2));

    const projectUrl = `/${targetSlug}/`;

    return res.json({
      success: true,
      message: 'Project deployed from pasted code!',
      slug: targetSlug,
      url: projectUrl,
      project: {
        ...metadata,
        url: projectUrl
      }
    });
  } catch (err) {
    console.error('Paste-Deploy Error:', err);
    return res.status(500).json({ success: false, message: 'Deploy from code failed: ' + err.message });
  }
});

// API: Re-upload / Update Project Files or Metadata
app.post('/api/projects/:slug/update', requireAuth, upload.single('file'), (req, res) => {
  const tempFilePath = req.file ? req.file.path : null;

  try {
    const rawSlug = req.params.slug;
    const safeSlug = path.basename(rawSlug);
    const targetPath = path.join(PROJECTS_DIR, safeSlug);
    const metaPath = path.join(targetPath, '.metadata.json');

    if (!fs.existsSync(targetPath)) {
      if (tempFilePath && fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
      return res.status(404).json({ success: false, message: 'Project not found.' });
    }

    let metadata = {};
    if (fs.existsSync(metaPath)) {
      try {
        metadata = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      } catch (e) {}
    }

    // Authorization check — reqUserEmail comes from the server-verified token, never the client
    const reqUserEmail = req.authUser.email;
    const projectAuthorEmail = (metadata.author && metadata.author.email) ? metadata.author.email : '';

    if (projectAuthorEmail && reqUserEmail && projectAuthorEmail.toLowerCase() !== reqUserEmail.toLowerCase() && !isAdmin(reqUserEmail)) {
      if (tempFilePath && fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
      return res.status(403).json({
        success: false,
        message: `Permission denied: Only ${projectAuthorEmail} can update this project.`
      });
    }

    // Update File if provided
    if (req.file) {
      // Snapshot the current live files before they get wiped — enables rollback
      snapshotProjectFiles(targetPath);
      const originalName = req.file.originalname;
      const ext = path.extname(originalName).toLowerCase();

      // Clear existing project files except .metadata.json
      const existingItems = fs.readdirSync(targetPath);
      for (const item of existingItems) {
        if (item !== '.metadata.json') {
          fs.rmSync(path.join(targetPath, item), { recursive: true, force: true });
        }
      }

      if (ext === '.zip') {
        metadata.fileType = 'zip';
        const zip = new AdmZip(tempFilePath);
        zip.extractAllTo(targetPath, true);

        // Flatten subfolder if zip contained a single root directory
        const contents = fs.readdirSync(targetPath).filter(i => i !== '.metadata.json');
        if (contents.length === 1) {
          const singleSubfolder = path.join(targetPath, contents[0]);
          if (fs.statSync(singleSubfolder).isDirectory()) {
            const subContents = fs.readdirSync(singleSubfolder);
            for (const item of subContents) {
              fs.renameSync(path.join(singleSubfolder, item), path.join(targetPath, item));
            }
            fs.rmdirSync(singleSubfolder);
          }
        }
      } else if (ext === '.html' || ext === '.htm') {
        metadata.fileType = 'html';
        const destPath = path.join(targetPath, 'index.html');
        fs.copyFileSync(tempFilePath, destPath);
      }
      metadata.originalFileName = originalName;
      if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
    }
    // Update File from pasted HTML code (only when no file was uploaded — a chosen file always wins)
    const pastedCode = (req.body.code || '').trim();
    if (!req.file && pastedCode) {
      if (Buffer.byteLength(pastedCode, 'utf8') > MAX_FILE_SIZE_BYTES) {
        return res.status(400).json({
          success: false,
          message: `Pasted HTML code exceeds the 50 MB size limit. Your code size: ${(Buffer.byteLength(pastedCode, 'utf8') / (1024 * 1024)).toFixed(1)} MB.`
        });
      }
      // Snapshot the previous version before overwriting
      snapshotProjectFiles(targetPath);
      metadata.fileType = 'html';
      metadata.originalFileName = '(pasted code)';
      fs.writeFileSync(path.join(targetPath, 'index.html'), pastedCode, 'utf8');
    }

    // Update fields
    if (req.body.title) metadata.title = req.body.title.trim();
    if (req.body.description !== undefined) metadata.description = req.body.description.trim();
    if (req.body.space) metadata.space = req.body.space.trim();
    if (['public', 'private', 'self'].includes(req.body.visibility)) metadata.visibility = req.body.visibility;
    metadata.updatedAt = new Date().toISOString();

    const stats = getFolderStats(targetPath);
    metadata.sizeBytes = stats.totalSize;
    metadata.fileCount = stats.fileCount;

    fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2));

    return res.json({
      success: true,
      message: 'Project updated successfully!',
      project: metadata
    });
  } catch(err) {
    if (tempFilePath && fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
    console.error('Update Error:', err);
    return res.status(500).json({ success: false, message: 'Update failed: ' + err.message });
  }
});

// API: List version history (snapshots) for a project
app.get('/api/projects/:slug/history', softAuth, (req, res) => {
  try {
    const safeSlug = path.basename(req.params.slug);
    const targetPath = path.join(PROJECTS_DIR, safeSlug);
    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, message: 'Project not found.' });
    }
    const versionsDir = path.join(targetPath, '.versions');
    const versions = [];
    if (fs.existsSync(versionsDir)) {
      for (const entry of fs.readdirSync(versionsDir, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        const vPath = path.join(versionsDir, entry.name);
        // 2026-10-01T08-18-01-884Z -> 2026-10-01T08:18:01.884Z
        const prettyStamp = entry.name
          .replace(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})-(\d{3})Z$/, '$1-$2-$3T$4:$5:$6.$7Z');
        const stats = getFolderStats(vPath);
        versions.push({
          id: entry.name,
          created: prettyStamp,
          sizeBytes: stats.totalSize,
          fileCount: stats.fileCount
        });
      }
    }
    versions.sort((a, b) => b.created.localeCompare(a.created)); // newest first
    return res.json({ success: true, versions });
  } catch (err) {
    console.error('History Error:', err);
    return res.status(500).json({ success: false, message: 'Failed to read version history: ' + err.message });
  }
});

// API: Download a specific version snapshot as .zip
app.get('/api/projects/:slug/history/:versionId/download', softAuth, (req, res) => {
  try {
    const safeSlug = path.basename(req.params.slug);
    const safeVersionId = path.basename(req.params.versionId);
    const targetPath = path.join(PROJECTS_DIR, safeSlug);
    const snapshotPath = path.join(targetPath, '.versions', safeVersionId);
    if (!fs.existsSync(snapshotPath) || !fs.statSync(snapshotPath).isDirectory()) {
      return res.status(404).json({ success: false, message: 'Version not found.' });
    }
    const zip = new AdmZip();
    zip.addLocalFolder(snapshotPath);
    res.set('Content-Type', 'application/zip');
    res.set('Content-Disposition', `attachment; filename="${safeSlug}-${safeVersionId}.zip"`);
    return res.send(zip.toBuffer());
  } catch (err) {
    console.error('Version Download Error:', err);
    return res.status(500).json({ success: false, message: 'Failed to build version download: ' + err.message });
  }
});

// API: Rollback a project to a previous version snapshot
app.post('/api/projects/:slug/rollback', requireAuth, (req, res) => {
  try {
    const safeSlug = path.basename(req.params.slug);
    const safeVersionId = path.basename((req.body.versionId || '').trim());
    const targetPath = path.join(PROJECTS_DIR, safeSlug);
    const snapshotPath = path.join(targetPath, '.versions', safeVersionId);

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, message: 'Project not found.' });
    }
    if (!safeVersionId || !fs.existsSync(snapshotPath) || !fs.statSync(snapshotPath).isDirectory()) {
      return res.status(400).json({ success: false, message: 'Invalid or unknown versionId.' });
    }

    const metaPath = path.join(targetPath, '.metadata.json');
    let metadata = {};
    if (fs.existsSync(metaPath)) {
      try { metadata = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch (e) {}
    }
    const reqUserEmail = req.authUser.email;
    const projectAuthorEmail = (metadata.author && metadata.author.email) ? metadata.author.email : '';
    if (projectAuthorEmail && reqUserEmail && projectAuthorEmail.toLowerCase() !== reqUserEmail.toLowerCase() && !isAdmin(reqUserEmail)) {
      return res.status(403).json({ success: false, message: `Permission denied: Only ${projectAuthorEmail} can roll back this project.` });
    }

    // Snapshot the CURRENT live state first, so the rollback itself is undoable
    snapshotProjectFiles(targetPath);

    // Wipe live files (keep .versions)
    for (const item of fs.readdirSync(targetPath)) {
      if (!item.startsWith('.')) fs.rmSync(path.join(targetPath, item), { recursive: true, force: true });
    }

    // Restore snapshot files to live
    for (const item of fs.readdirSync(snapshotPath)) {
      fs.cpSync(path.join(snapshotPath, item), path.join(targetPath, item), { recursive: true });
    }

    const stats = getFolderStats(targetPath);
    metadata.sizeBytes = stats.totalSize;
    metadata.fileCount = stats.fileCount;
    metadata.updatedAt = new Date().toISOString();
    fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2));

    return res.json({ success: true, message: `Project rolled back to version ${safeVersionId}.`, project: metadata });
  } catch (err) {
    console.error('Rollback Error:', err);
    return res.status(500).json({ success: false, message: 'Rollback failed: ' + err.message });
  }
});

// API: Update Project Description / Metadata (Author Only)
app.put('/api/projects/:slug', requireAuth, (req, res) => {
  try {
    const rawSlug = req.params.slug;
    const safeSlug = path.basename(rawSlug);
    const targetPath = path.join(PROJECTS_DIR, safeSlug);
    const metaPath = path.join(targetPath, '.metadata.json');

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, message: 'Project not found.' });
    }

    let metadata = {};
    if (fs.existsSync(metaPath)) {
      try {
        metadata = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      } catch (e) {}
    }

    const reqUserEmail = req.authUser.email;
    const projectAuthorEmail = (metadata.author && metadata.author.email) ? metadata.author.email : '';

    // Check ownership authorization
    if (projectAuthorEmail && reqUserEmail && projectAuthorEmail.toLowerCase() !== reqUserEmail.toLowerCase() && !isAdmin(reqUserEmail)) {
      return res.status(403).json({
        success: false,
        message: 'Permission denied: Only the original creator can edit this project.'
      });
    }

    if (req.body.title) metadata.title = req.body.title.trim();
    if (req.body.description !== undefined) metadata.description = req.body.description.trim();
    if (req.body.space) metadata.space = req.body.space.trim();
    if (['public', 'private', 'self'].includes(req.body.visibility)) metadata.visibility = req.body.visibility;
    metadata.updatedAt = new Date().toISOString();

    fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2));

    return res.json({ success: true, message: 'Project details updated successfully.', metadata });
  } catch (err) {
    console.error('Update Error:', err);
    return res.status(500).json({ success: false, message: 'Failed to update project: ' + err.message });
  }
});

// API: Delete Project (Author Only)
app.delete('/api/projects/:slug', requireAuth, (req, res) => {
  try {
    const rawSlug = req.params.slug;
    const safeSlug = path.basename(rawSlug); // Protect against traversal
    const targetPath = path.join(PROJECTS_DIR, safeSlug);
    const metaPath = path.join(targetPath, '.metadata.json');

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, message: 'Project not found.' });
    }

    let metadata = {};
    if (fs.existsSync(metaPath)) {
      try {
        metadata = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      } catch (e) {}
    }

    // Ownership Verification — reqUserEmail comes from the server-verified token, never the client
    const reqUserEmail = req.authUser.email;
    const projectAuthorEmail = (metadata.author && metadata.author.email) ? metadata.author.email : '';

    if (projectAuthorEmail && reqUserEmail && projectAuthorEmail.toLowerCase() !== reqUserEmail.toLowerCase() && !isAdmin(reqUserEmail)) {
      return res.status(403).json({
        success: false,
        message: `Permission denied: Only the creator (${projectAuthorEmail}) can delete this project.`
      });
    }

    fs.rmSync(targetPath, { recursive: true, force: true });
    return res.json({ success: true, message: `Project '${safeSlug}' deleted successfully.` });
  } catch (err) {
    console.error('Delete Error:', err);
    return res.status(500).json({ success: false, message: 'Failed to delete project: ' + err.message });
  }
});

// API: Archive / Unarchive a project (Author or admin only) — takes it offline without deleting it
app.post('/api/projects/:slug/archive', requireAuth, (req, res) => {
  try {
    const safeSlug = path.basename(req.params.slug);
    const targetPath = path.join(PROJECTS_DIR, safeSlug);
    const metaPath = path.join(targetPath, '.metadata.json');

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, message: 'Project not found.' });
    }

    let metadata = {};
    if (fs.existsSync(metaPath)) {
      try { metadata = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch (e) {}
    }

    const reqUserEmail = req.authUser.email;
    const projectAuthorEmail = (metadata.author && metadata.author.email) ? metadata.author.email : '';
    if (projectAuthorEmail && projectAuthorEmail.toLowerCase() !== reqUserEmail.toLowerCase() && !isAdmin(reqUserEmail)) {
      return res.status(403).json({ success: false, message: `Permission denied: Only ${projectAuthorEmail} can archive this project.` });
    }

    metadata.archived = req.body && req.body.archived === false ? false : !metadata.archived;
    metadata.updatedAt = new Date().toISOString();
    fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2));

    return res.json({ success: true, archived: metadata.archived, message: metadata.archived ? 'Project archived.' : 'Project restored.' });
  } catch (err) {
    console.error('Archive Error:', err);
    return res.status(500).json({ success: false, message: 'Failed to update archive state: ' + err.message });
  }
});

// API: Download a project's hosted files as a .zip (respects "self" visibility like the live URL does)
app.get('/api/projects/:slug/download', softAuth, (req, res) => {
  try {
    const safeSlug = path.basename(req.params.slug);
    const targetPath = path.join(PROJECTS_DIR, safeSlug);
    const metaPath = path.join(targetPath, '.metadata.json');

    if (!fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, message: 'Project not found.' });
    }

    let metadata = {};
    if (fs.existsSync(metaPath)) {
      try { metadata = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch (e) {}
    }

    if ((metadata.visibility || 'public') === 'self') {
      const requesterEmail = req.authUser ? req.authUser.email.toLowerCase() : null;
      const ownerEmail = (metadata.author && metadata.author.email) ? metadata.author.email.toLowerCase() : '';
      if (!requesterEmail || (requesterEmail !== ownerEmail && !isAdmin(requesterEmail))) {
        return res.status(403).json({ success: false, message: 'You do not have access to download this project.' });
      }
    }

    // Build the zip from only visible files — skip internal/hidden entries
    // (.metadata.json and the entire .versions/ snapshot tree) so the download
    // is exactly what is live on the web.
    const source = new AdmZip();
    source.addLocalFolder(targetPath);
    const visible = new AdmZip();
    for (const entry of source.getEntries()) {
      if (entry.entryName.split('/').some(seg => seg.startsWith('.'))) continue;
      visible.addFile(entry.entryName, entry.getData());
    }
    res.set('Content-Type', 'application/zip');
    res.set('Content-Disposition', `attachment; filename="${safeSlug}.zip"`);
    return res.send(visible.toBuffer());
  } catch (err) {
    console.error('Download Error:', err);
    return res.status(500).json({ success: false, message: 'Failed to build download: ' + err.message });
  }
});

// ============================================================================
// AFFILIATE PROGRAM
// Partners (from the public landing page /nct-hub) get a unique referral code.
// They share https://html.nctprosperatech.com/nct-hub?ref=CODE — every click is
// tracked, and when the owner/admin records an order that came from a partner,
// the partner's balance grows by their commission rate. Payouts are recorded
// manually by the owner (no automatic money movement — keep it auditable).
// Data lives in affiliate.json (gitignored, same pattern as users.json).
// ============================================================================
const AFFILIATE_FILE = path.join(__dirname, 'affiliate.json');
function loadAffiliateData() {
  try { return JSON.parse(fs.readFileSync(AFFILIATE_FILE, 'utf8')); } catch (e) { return null; }
}
let AFFILIATE = loadAffiliateData();
if (!AFFILIATE || !AFFILIATE.partners) {
  AFFILIATE = {
    settings: { defaultCommissionRate: 20, minPayout: 500 },
    partners: {},
    orders: [],
    clicks: []
  };
}
function saveAffiliate() {
  fs.writeFileSync(AFFILIATE_FILE, JSON.stringify(AFFILIATE, null, 2));
}
function makeAffiliateCode(name) {
  const base = (String(name || 'partner').replace(/[^a-z0-9]/gi, '') || 'p').slice(0, 8).toLowerCase();
  const rand = crypto.randomBytes(3).toString('hex').slice(0, 4);
  return base + '-' + rand;
}

// --- Partner public portal helpers -------------------------------------------
function publicPartnerView(code) {
  const p = AFFILIATE.partners[code.toLowerCase()];
  if (!p) return null;
  const base = process.env.PUBLIC_BASE_URL || 'https://html.nctprosperatech.com';
  return {
    code: p.code,
    name: p.name,
    commissionRate: p.commissionRate,
    clicks: p.clicks || 0,
    ordersCount: p.ordersCount || 0,
    totalCommission: p.balance || 0,
    link: `${base}/nct-hub?ref=${p.code}`
  };
}

// API: Public — join the affiliate program. Returns the partner's referral code/link.
// Re-joining with the same email returns the existing partnership (no duplicates).
app.post('/api/affiliate/join', (req, res) => {
  try {
    const name = String(req.body.name || '').trim().slice(0, 60);
    const email = String(req.body.email || '').trim().toLowerCase().slice(0, 120);
    if (!name) return res.status(400).json({ success: false, message: 'Please enter your name.' });
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success: false, message: 'Please enter a valid email.' });

    let existing = null;
    for (const p of Object.values(AFFILIATE.partners)) if (p.email === email) { existing = p; break; }
    if (existing) {
      return res.json({ success: true, existing: true, partner: publicPartnerView(existing.code) });
    }

    let code = makeAffiliateCode(name);
    while (AFFILIATE.partners[code]) code = makeAffiliateCode(name) + Math.floor(Math.random() * 90 + 10);
    const rate = Math.min(50, Math.max(5, Number(req.body.commissionRate) || AFFILIATE.settings.defaultCommissionRate));
    AFFILIATE.partners[code] = {
      code, name, email,
      commissionRate: rate,
      clicks: 0, ordersCount: 0, balance: 0,
      paidOut: 0,
      createdAt: new Date().toISOString()
    };
    saveAffiliate();
    return res.json({ success: true, existing: false, partner: publicPartnerView(code) });
  } catch (err) {
    console.error('Affiliate join error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// API: Public — track a referral click (landing page calls this when ?ref=CODE is present).
app.post('/api/affiliate/track', (req, res) => {
  try {
    const code = String(req.body.code || '').toLowerCase().slice(0, 32);
    if (!code) return res.json({ success: false, message: 'Missing code.' });
    const p = AFFILIATE.partners[code];
    if (!p) return res.status(404).json({ success: false, message: 'Unknown code.' });
    p.clicks = (p.clicks || 0) + 1;
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || '';
    AFFILIATE.clicks.push({ code, ip, ua: String(req.headers['user-agent'] || '').slice(0, 120), at: new Date().toISOString() });
    // keep the click log bounded (~10k entries)
    if (AFFILIATE.clicks.length > 10000) AFFILIATE.clicks = AFFILIATE.clicks.slice(-5000);
    saveAffiliate();
    return res.json({ success: true, clicks: p.clicks });
  } catch (err) {
    console.error('Affiliate track error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// API: Public — partner portal lookup (own stats + link) by code
app.get('/api/affiliate/portal/:code', (req, res) => {
  const view = publicPartnerView(req.params.code);
  if (!view) return res.status(404).json({ success: false, message: 'Not found.' });
  res.json({ success: true, partner: view });
});

// Middleware: require an admin session via the nct_session cookie (set by the dashboard
// login flows). Used by the affiliate admin console page, which can't carry a Bearer token.
function requireCookieAdmin(req, res, next) {
  const email = getSessionEmail(req);
  if (!email || !isAdmin(email)) {
    return res.status(403).json({ success: false, message: 'Admin session required. Sign in on the dashboard first.' });
  }
  req.authUser = { email };
  next();
}

// API: Owner/admin — record an order that came from a partner → credit commission
app.post('/api/affiliate/order', requireCookieAdmin, (req, res) => {
  try {
    if (!isAdmin(req.authUser.email)) return res.status(403).json({ success: false, message: 'Admin only.' });
    const code = String(req.body.code || '').toLowerCase().trim();
    const amount = Number(req.body.amount);
    if (!code || !AFFILIATE.partners[code]) return res.status(400).json({ success: false, message: 'Unknown partner code.' });
    if (!isFinite(amount) || amount <= 0) return res.status(400).json({ success: false, message: 'Invalid amount.' });
    const note = String(req.body.note || '').slice(0, 200);
    const p = AFFILIATE.partners[code];
    const commission = Math.round(amount * (p.commissionRate / 100));
    const order = {
      id: 'ord-' + crypto.randomBytes(5).toString('hex'),
      code, amount, commission, note,
      by: req.authUser.email, at: new Date().toISOString()
    };
    AFFILIATE.orders.push(order);
    p.balance = (p.balance || 0) + commission;
    p.ordersCount = (p.ordersCount || 0) + 1;
    saveAffiliate();
    return res.json({ success: true, order, balance: p.balance });
  } catch (err) {
    console.error('Affiliate order error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// API: Owner/admin — record a payout (reduces balance, logs it)
app.post('/api/affiliate/payout', requireCookieAdmin, (req, res) => {
  try {
    if (!isAdmin(req.authUser.email)) return res.status(403).json({ success: false, message: 'Admin only.' });
    const code = String(req.body.code || '').toLowerCase().trim();
    const p = AFFILIATE.partners[code];
    if (!p) return res.status(400).json({ success: false, message: 'Unknown partner code.' });
    const amount = Number(req.body.amount);
    if (!isFinite(amount) || amount <= 0 || amount > (p.balance || 0)) return res.status(400).json({ success: false, message: 'Invalid amount (max = balance).' });
    const method = String(req.body.method || 'transfer').slice(0, 40);
    p.balance -= amount;
    p.paidOut = (p.paidOut || 0) + amount;
    p.payouts = p.payouts || [];
    p.payouts.push({ amount, method, by: req.authUser.email, at: new Date().toISOString() });
    saveAffiliate();
    return res.json({ success: true, balance: p.balance, paidOut: p.paidOut });
  } catch (err) {
    console.error('Affiliate payout error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// API: Owner/admin — full affiliate dashboard data
app.get('/api/affiliate/summary', requireCookieAdmin, (req, res) => {
  try {
    if (!isAdmin(req.authUser.email)) return res.status(403).json({ success: false, message: 'Admin only.' });
    const partners = Object.values(AFFILIATE.partners).map(p => ({
      code: p.code, name: p.name, email: p.email,
      commissionRate: p.commissionRate,
      clicks: p.clicks || 0, ordersCount: p.ordersCount || 0,
      balance: p.balance || 0, paidOut: p.paidOut || 0,
      createdAt: p.createdAt
    })).sort((a, b) => (b.balance + b.paidOut) - (a.balance + a.paidOut));
    const totals = {
      partners: partners.length,
      totalClicks: partners.reduce((s, p) => s + p.clicks, 0),
      totalOrders: AFFILIATE.orders.length,
      totalCommission: AFFILIATE.orders.reduce((s, o) => s + o.commission, 0),
      totalPaidOut: partners.reduce((s, p) => s + (p.paidOut || 0), 0),
      totalBalance: partners.reduce((s, p) => s + (p.balance || 0), 0),
      recentClicks: (AFFILIATE.clicks || []).slice(-25).reverse()
    };
    return res.json({ success: true, totals, partners, orders: AFFILIATE.orders.slice(-50).reverse() });
  } catch (err) {
    console.error('Affiliate summary error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// Serve hosted projects at both /projects/<slug> and directly at /<slug>, gated by visibility
function resolveProjectRequest(reqPath) {
  const strippedPath = reqPath.startsWith('/projects/') ? reqPath.slice('/projects'.length) : reqPath;
  const parts = strippedPath.split('/').filter(Boolean);
  if (parts.length === 0) return null;

  const slug = parts[0];
  // Never serve version-history snapshots over the web
  if (parts.some(p => p.startsWith('.'))) return null;
  let projectDir = path.join(PROJECTS_DIR, slug);
  if (!fs.existsSync(projectDir) || !fs.statSync(projectDir).isDirectory()) {
    try {
      const entries = fs.readdirSync(PROJECTS_DIR);
      const match = entries.find(e => e.toLowerCase() === slug.toLowerCase() && !e.startsWith('.'));
      if (match) {
        projectDir = path.join(PROJECTS_DIR, match);
      } else {
        return null;
      }
    } catch (e) {
      return null;
    }
  }

  const subPath = parts.slice(1).join('/');
  let targetFile = path.join(projectDir, subPath);
  if (fs.existsSync(targetFile) && fs.statSync(targetFile).isDirectory()) {
    targetFile = path.join(targetFile, 'index.html');
  }
  if (!fs.existsSync(targetFile) || fs.statSync(targetFile).isDirectory()) return null;

  return { projectDir, subPath, targetFile };
}

app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path === '/' || req.path === '/index.html') {
    return next();
  }

  // Handle typo alias /Fram-Live or /projects/Fram-Live -> redirect to /farm-live/
  if (/^\/(?:projects\/)?fram-live(?:\/.*)?$/i.test(req.path)) {
    const rest = req.path.replace(/^\/(?:projects\/)?fram-live/i, '');
    return res.redirect(301, '/farm-live' + (rest || '/'));
  }

  const resolved = resolveProjectRequest(req.path);
  if (!resolved) return next();

  const { projectDir, subPath, targetFile } = resolved;
  const metaPath = path.join(projectDir, '.metadata.json');
  let meta = {};
  if (fs.existsSync(metaPath)) {
    try { meta = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch (e) {}
  }

  if (meta.archived) {
    return res.status(410).send('<h1>410 — Project Archived</h1><p>This project has been archived by its owner and is no longer live.</p>');
  }

  if ((meta.visibility || 'public') === 'self') {
    const sessionEmail = getSessionEmail(req);
    const ownerEmail = (meta.author && meta.author.email) ? meta.author.email.toLowerCase() : '';
    const allowed = sessionEmail && (sessionEmail.toLowerCase() === ownerEmail || isAdmin(sessionEmail));
    if (!allowed) {
      return res.status(403).send('<h1>403 — Private Project</h1><p>You do not have access to view this project.</p>');
    }
  }

  // Asynchronously track view count on main index access
  if (!subPath || subPath === 'index.html') {
    try {
      meta.viewsCount = (meta.viewsCount || 0) + 1;
      fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2));
    } catch (e) {}
  }
  return res.sendFile(targetFile);
});

// Fallback to Dashboard index.html for SPA routes
app.use((req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🚀 HTML Auto-Deploy Server running on port ${PORT}`);
  console.log(`🌐 Local URL: http://localhost:${PORT}`);
  console.log(`📁 Projects hosted at: http://localhost:${PORT}/projects/<slug>`);
  console.log(`====================================================`);
});
