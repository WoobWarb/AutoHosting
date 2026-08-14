# ⚡ NCT AutoHosting Hub (Web Deploy Manager)

> **Self-hosted Static HTML & Web Assets Auto-Deployment Platform**  
> Host, manage, showcase, and update web projects instantly with automatic subpath routing, Google OAuth, and Spaces categorization.

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-5.x-blue.svg)](https://expressjs.com/)
[![License](https://img.shields.io/badge/License-ISC-purple.svg)](LICENSE)
[![Production](https://img.shields.io/badge/Production-Live-success.svg)](https://html.nctprosperatech.com/)

---

## 🌟 Key Features

### 1. 📁 Spaces & Category Tabs (`+ Create new space`)
- Organize web projects into dedicated Spaces / Folders (e.g. `Client Projects`, `Smart City Framework`, `Internal Tools`).
- Filter and navigate projects quickly with dynamic counter badges.
- Create new spaces on the fly with the `+` button.

### 2. 🚀 Instant Auto-Deploy & Direct URL Routing
- Upload standalone **`.html`** files or full **`.zip`** web bundles (containing HTML, CSS, JS, Images, Fonts).
- Automatically unpacks and serves at direct paths:
  - `https://html.nctprosperatech.com/<project-slug>`
  - `https://html.nctprosperatech.com/projects/<project-slug>`

### 3. 📊 Modern Table & Grid Showcase Views
- **Table List View**: View status (`🟢 Public`), direct project link, Space tag, modified date, view counts, and quick actions.
- **Grid Cards View**: Rich Glassmorphic card design with author avatars and time-ago indicators.
- **Switchable View Modes**: Toggle between `≡ Table` and `⊞ Grid` with a single click.

### 4. 🔲 QR Code & Live Preview
- **Instant QR Code**: Generate high-res QR codes for instant mobile scanning and testing.
- **Full-Screen Live Preview**: Preview websites inside an interactive modal before opening in full tab.
- **One-Click URL Copy**: Copy direct public URLs to clipboard.

### 5. ✏️ Project Updates & Re-upload
- Replace files or update title, description, and Space without changing the URL slug.
- Protect modifications so only the original project creator can edit or delete.

### 6. 🔑 Official Google Sign-In & Ownership Protection
- Integrated with **Google Identity Services (OAuth 2.0)**.
- Public visitors can browse and preview all projects.
- Deployment, updates, and deletions are protected by Google Account authentication.

### 7. 🔄 GitHub Webhook Auto Deploy (CI/CD)
- Built-in webhook endpoint `/api/webhook/deploy`.
- Every `git push` to `main` automatically pulls latest code, installs dependencies, and restarts PM2 on the VPS in seconds.

### 8. 🛡️ Storage Quotas & Security
- **File size limit**: Up to 50 MB per upload.
- **Per-user quota**: 500 MB for NCT Team members (`@nctprosperatech.com`), 200 MB for public users.
- **Path traversal protection** & sanitized slug generation.

---

## 🛠️ Tech Stack

- **Backend**: Node.js, Express, Multer, Adm-Zip, Slugify, CORS
- **Frontend**: Vanilla HTML5, CSS3 (Glassmorphic Design, Plus Jakarta Sans, Prompt), JavaScript
- **Auth**: Google Identity Services (GIS OAuth 2.0)
- **Deployment & Infra**: Ubuntu VPS (`178.128.59.217`), PM2 Process Manager, Nginx Reverse Proxy, Certbot SSL

---

## 📁 Project Structure

```
AutoHosting/
├── public/
│   └── index.html             # Glassmorphic Web Dashboard UI
├── projects/                  # Dynamic hosted web projects storage
│   ├── _spaces.json           # Spaces registry
│   └── smart-city-framework/  # Example hosted project
│       ├── .metadata.json     # Project metadata (author, views, space)
│       └── index.html         # Hosted HTML entrypoint
├── server.js                  # Express backend engine & routing
├── package.json               # Dependencies & scripts
├── README.md                  # Project documentation
├── README_DEPLOY.md           # VPS deployment instructions
└── .gitignore                 # Excluded directories & archives
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Node.js 18+ LTS
- npm

### 2. Local Installation
```bash
# Clone the repository
git clone https://github.com/WoobWarb/AutoHosting.git
cd AutoHosting

# Install dependencies
npm install

# Start development server
node server.js
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🌐 Production Deployment (VPS)

### 1. Server Setup (Ubuntu / Debian)
```bash
# SSH into VPS
ssh root@178.128.59.217

# Install Node.js & PM2
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs nginx git
sudo npm install -g pm2

# Clone and run
mkdir -p /var/www/html-uploader
cd /var/www/html-uploader
git clone https://github.com/WoobWarb/AutoHosting.git .
npm install --production
pm2 start server.js --name "html-uploader"
pm2 save
pm2 startup
```

### 2. Nginx Reverse Proxy Configuration
```nginx
server {
    listen 80;
    server_name html.nctprosperatech.com;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## 📡 REST API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/projects` | `GET` | Get all deployed projects |
| `/api/upload` | `POST` | Upload new `.html` or `.zip` project |
| `/api/projects/:slug/update` | `POST` | Re-upload files or update metadata |
| `/api/projects/:slug` | `PUT` | Update title/description |
| `/api/projects/:slug` | `DELETE` | Delete project (Author only) |
| `/api/spaces` | `GET` | Get spaces and project counts |
| `/api/spaces` | `POST` | Create a new space |
| `/api/spaces/:name` | `DELETE` | Delete a space |
| `/api/webhook/deploy` | `POST` | GitHub Auto Deploy Webhook |

---

## 📄 License & Copyright

© 2026 **NCT ProsperaTech**. All rights reserved.  
Powered by NCT Cloud Infrastructure & Gemini AI.
