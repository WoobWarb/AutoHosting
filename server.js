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

// Middleware: require a valid Google ID token in the Authorization header.
// Attaches the server-verified identity to req.authUser — never trust a client-supplied email.
async function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const user = await verifyGoogleToken(idToken);
  if (!user) {
    return res.status(401).json({ success: false, message: 'Authentication required. Please sign in with Google.' });
  }
  req.authUser = user;
  next();
}

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

// Serve hosted projects dynamically at /projects/<slug>
app.use('/projects', express.static(PROJECTS_DIR));

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
app.get('/api/projects', (req, res) => {
  try {
    const entries = fs.readdirSync(PROJECTS_DIR, { withFileTypes: true });
    const projects = [];

    for (const entry of entries) {
      if (entry.isDirectory()) {
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

        projects.push({
          slug,
          title: metadata.title || slug,
          description: metadata.description || 'No description provided.',
          author: metadata.author || { name: 'Anonymous', email: '', picture: '' },
          space: metadata.space || 'General',
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

    // Sort newest first
    projects.sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt));
    res.json({ success: true, projects });
  } catch (err) {
    console.error('Error fetching projects:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// Storage Quota Settings (Adaptable for VPS Capacity)
const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50MB per upload
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

    // Author identity comes only from the server-verified Google token — never from client input
    const author = req.authUser;

    // Enforce Per-User Storage Quota
    const userEmail = author.email.toLowerCase();
    const isNctTeam = userEmail.endsWith('@nctprosperatech.com');
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

    if (projectAuthorEmail && reqUserEmail && projectAuthorEmail.toLowerCase() !== reqUserEmail.toLowerCase()) {
      if (tempFilePath && fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
      return res.status(403).json({
        success: false,
        message: `Permission denied: Only ${projectAuthorEmail} can update this project.`
      });
    }

    // Update File if provided
    if (req.file) {
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

    // Update fields
    if (req.body.title) metadata.title = req.body.title.trim();
    if (req.body.description !== undefined) metadata.description = req.body.description.trim();
    if (req.body.space) metadata.space = req.body.space.trim();
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
    if (projectAuthorEmail && reqUserEmail && projectAuthorEmail.toLowerCase() !== reqUserEmail.toLowerCase()) {
      return res.status(403).json({
        success: false,
        message: 'Permission denied: Only the original creator can edit this project.'
      });
    }

    if (req.body.title) metadata.title = req.body.title.trim();
    if (req.body.description !== undefined) metadata.description = req.body.description.trim();
    if (req.body.space) metadata.space = req.body.space.trim();
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

    if (projectAuthorEmail && reqUserEmail && projectAuthorEmail.toLowerCase() !== reqUserEmail.toLowerCase()) {
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

// Serve hosted projects dynamically at /projects/<slug> and directly at /<slug>
app.use('/projects', express.static(PROJECTS_DIR));

// Dynamic Router for direct domain paths: html.nctprosperatech.com/<slug>
app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path === '/' || req.path === '/index.html') {
    return next();
  }

  const parts = req.path.split('/').filter(Boolean);
  if (parts.length > 0) {
    const slug = parts[0];
    const projectDir = path.join(PROJECTS_DIR, slug);

    if (fs.existsSync(projectDir) && fs.statSync(projectDir).isDirectory()) {
      const subPath = parts.slice(1).join('/');
      let targetFile = path.join(projectDir, subPath);

      if (fs.existsSync(targetFile) && fs.statSync(targetFile).isDirectory()) {
        targetFile = path.join(targetFile, 'index.html');
      }

      if (fs.existsSync(targetFile) && !fs.statSync(targetFile).isDirectory()) {
        // Asynchronously track view count on main index access
        if (!subPath || subPath === 'index.html') {
          try {
            const metaPath = path.join(projectDir, '.metadata.json');
            if (fs.existsSync(metaPath)) {
              const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
              meta.viewsCount = (meta.viewsCount || 0) + 1;
              fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2));
            }
          } catch(e) {}
        }
        return res.sendFile(targetFile);
      }
    }
  }
  next();
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
