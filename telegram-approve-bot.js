// Telegram Approve Bot — polls dashboard for pending access requests,
// notifies the project owner (or admin fallback) with Approve/Deny buttons.
'use strict';
const fs = require('fs');
const path = require('path');

// Secrets come from environment (bot.env, gitignored) — never commit real values.
function loadEnvFile() {
  try {
    const f = path.join(__dirname, 'bot.env');
    if (fs.existsSync(f)) {
      for (const line of fs.readFileSync(f, 'utf8').split(/\r?\n/)) {
        const m = line.match(/^([A-Z_]+)=(.*)$/);
        if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
      }
    }
  } catch (e) {}
}
loadEnvFile();
const BOT_TOKEN = process.env.BOT_TOKEN;
const API_BASE = process.env.BOT_API_BASE || 'http://127.0.0.1:3000';
const BOT_USER = process.env.BOT_USER;
const BOT_PASS = process.env.BOT_PASS;
if (!BOT_TOKEN || !BOT_USER || !BOT_PASS) {
  console.error('Missing BOT_TOKEN/BOT_USER/BOT_PASS — copy bot.env.example to bot.env');
  process.exit(1);
}
const ADMIN_TG_ID = Number(process.env.ADMIN_TG_ID || 2017828914); // woob fallback

const STATE_FILE = path.join(__dirname, 'telegram_ids.json');
const POLL_MS = 8000;

// ---------- state ----------
let telegramIds = {};   // email -> tg chat id
let usernameIds = {};   // @username -> tg chat id
let idAnnounced = {};   // chat id -> true (ID already announced)
let registering = {};   // chat id -> true (waiting for email)
let seen = new Set();   // request ids already notified
let dashToken = null;

function loadState() {
  try {
    const s = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    telegramIds = s.telegramIds || {};
    usernameIds = s.usernameIds || {};
    idAnnounced = s.idAnnounced || {};
  } catch (e) { telegramIds = {}; usernameIds = {}; idAnnounced = {}; }
}
function saveState() {
  fs.writeFileSync(STATE_FILE, JSON.stringify({ telegramIds, usernameIds, idAnnounced }, null, 2));
}
// ---------- telegram api ----------
async function tg(method, params) {
  try {
    const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params)
    });
    const j = await r.json();
    if (!j.ok) console.error('TG', method, JSON.stringify(j).slice(0, 300));
    return j;
  } catch (e) { console.error('TG err', method, e.message); return { ok: false }; }
}

// ---------- dashboard api ----------
async function dashLogin() {
  const r = await fetch(API_BASE + '/api/pass/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: BOT_USER, password: BOT_PASS })
  });
  const j = await r.json();
  if (!j.success) throw new Error('login failed: ' + JSON.stringify(j));
  dashToken = j.token;
  console.log('dashboard login ok');
}
async function dash(method, urlPath, body) {
  const opts = { method, headers: { Authorization: 'Bearer ' + dashToken } };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(API_BASE + urlPath, opts);
  return r.json();
}

// ---------- resolve a target (numeric id or @username) ----------
function resolveTarget(v) {
  if (!v) return { id: null };
  const s = String(v).trim();
  if (/^\d+$/.test(s)) return { id: parseInt(s, 10) };
  if (s.startsWith('@')) {
    const u = s.toLowerCase();
    if (usernameIds[u]) return { id: usernameIds[u] };
    return { id: null, unknown: u };
  }
  return { id: null };
}

// ---------- notify owner ----------
async function notifyOwner(req) {
  // Priority: project's explicit telegramId > owner-email map > admin fallback
  const resolved = resolveTarget(req.telegramId);
  const emailTg = telegramIds[req.ownerEmail];
  // notify BOTH the project owner (telegramId / owner email) AND admin
  const targets = [];
  const primary = (resolved && resolved.id) || emailTg;
  if (primary) targets.push(primary);
  if (ADMIN_TG_ID && ADMIN_TG_ID !== primary) targets.push(ADMIN_TG_ID);
  if (!targets.length) targets.push(ADMIN_TG_ID);
  if (req.telegramId && !resolved.id) {
    console.warn('could not resolve telegramId', req.telegramId, '-> admin only');
  }
  const lines = [
    '🔔 New access request',
    '',
    'Project: ' + req.slug,
    'Name: ' + req.name,
    'Contact: ' + req.contact
  ];
  if (req.note) lines.push('Note: ' + req.note);
  lines.push('Owner: ' + (req.ownerEmail || '(none)'));
  if (req.telegramId) lines.push('TG ID: ' + req.telegramId);
  for (const chatId of targets) {
    await tg('sendMessage', {
      chat_id: chatId, text: lines.join('\n'),
      reply_markup: { inline_keyboard: [[
        { text: '✅ Approve', callback_data: 'approve:' + req.id },
        { text: '❌ Deny', callback_data: 'deny:' + req.id }
      ]] }
    });
    console.log('notified', chatId, 'for', req.slug, req.id);
  }
}

// ---------- poll requests ----------
async function pollRequests() {
  if (!dashToken) { try { await dashLogin(); } catch (e) { return; } }
  let data;
  try { data = await dash('GET', '/api/access/list'); } catch (e) { return; }
  if (!data.success) { dashToken = null; return; }
  for (const req of data.requests) {
    if (req.status === 'pending' && !seen.has(req.id)) {
      seen.add(req.id);
      await notifyOwner(req);
    }
  }
}

// ---------- handle telegram updates ----------
async function handleUpdate(u) {
  const msg = u.message;
  const cb = u.callback_query;

  if (msg && msg.text) {
    const chatId = msg.chat.id;
    if (msg.text === '/start') {
      if (msg.from && msg.from.username) {
        usernameIds['@' + msg.from.username.toLowerCase()] = chatId;
        saveState();
      }
      registering[chatId] = true;
      await tg('sendMessage', {
        chat_id: chatId,
        text: '👋 Approve Bot\n\nType the email you use in the dashboard (e.g. support@nctprosperatech.com) and I will send access requests to you.'
      });
      return;
    }
    if (msg.text === '/help') {
      await tg('sendMessage', { chat_id: chatId, text: 'Send /start to register your email. When someone requests access to your private project, I will message you with Approve/Deny buttons.\nSend /id to get your numeric Telegram ID.' });
      return;
    }
    if (msg.text === '/id') {
      if (msg.from && msg.from.username) {
        usernameIds['@' + msg.from.username.toLowerCase()] = chatId;
        saveState();
      }
      await tg('sendMessage', { chat_id: chatId, text: 'Your numeric Telegram ID: ' + chatId + (msg.from && msg.from.username ? '\nYour username: @' + msg.from.username : '') + '\nSend this number to the dashboard owner to be notified of access requests.' });
      return;
    }
    // auto-ID: first message from a new chat -> tell them their numeric ID
    if (!registering[chatId] && !idAnnounced[chatId]) {
      idAnnounced[chatId] = true;
      if (msg.from && msg.from.username) {
        usernameIds['@' + msg.from.username.toLowerCase()] = chatId;
      }
      saveState();
      await tg('sendMessage', { chat_id: chatId, text: 'Your numeric Telegram ID: ' + chatId + (msg.from && msg.from.username ? '\nYour username: @' + msg.from.username : '') + '\n\nSend this number (or your @username) to the dashboard owner, and they can put it in the project\'s Telegram ID field to receive access requests.\n\nSend /start to register your dashboard email instead.' });
      return;
    }
    if (registering[chatId]) {
      const email = msg.text.trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        await tg('sendMessage', { chat_id: chatId, text: 'That does not look like an email. Try again.' });
        return;
      }
      telegramIds[email] = chatId;
      saveState();
      delete registering[chatId];
      await tg('sendMessage', { chat_id: chatId, text: '✅ Saved ' + email + ' → your Telegram. You will receive access requests for projects owned by this email.' });
      return;
    }
    return;
  }

  if (cb) {
    const parts = cb.data.split(':');
    const action = parts[0];
    const reqId = parts.slice(1).join(':');
    const fromId = cb.from.id;
    let data;
    try { data = await dash('GET', '/api/access/list'); } catch (e) { return; }
    const req = (data.requests || []).find(r => r.id === reqId);
    if (!req || req.status !== 'pending') {
      await tg('answerCallbackQuery', { callback_query_id: cb.id, text: 'Request no longer pending.' });
      return;
    }
    const isOwner = telegramIds[req.ownerEmail] === fromId;
    const projResolved = resolveTarget(req.telegramId);
    const isProjectTg = projResolved.id && projResolved.id === fromId;
    const isAdmin = fromId === ADMIN_TG_ID;
    if (!isOwner && !isProjectTg && !isAdmin) {
      await tg('answerCallbackQuery', { callback_query_id: cb.id, text: 'You are not the owner of this project.' });
      return;
    }
    if (action === 'approve') {
      const result = await dash('POST', '/api/access/approve', { requestId: reqId });
      if (result.success) {
        await tg('editMessageText', {
          chat_id: cb.message.chat.id, message_id: cb.message.message_id,
          text: '✅ Approved ' + req.slug + '\n\nSend this link to ' + req.name + ' (valid 24h):\n' + result.shareUrl
        });
        console.log('approved', reqId, 'by', fromId);
      } else {
        await tg('answerCallbackQuery', { callback_query_id: cb.id, text: 'Approve failed: ' + (result.error || 'unknown') });
      }
    } else if (action === 'deny') {
      const result = await dash('POST', '/api/access/deny', { requestId: reqId });
      if (result.success) {
        await tg('editMessageText', {
          chat_id: cb.message.chat.id, message_id: cb.message.message_id,
          text: '❌ Denied request from ' + req.name + ' (' + req.contact + ') for ' + req.slug + '.'
        });
        console.log('denied', reqId, 'by', fromId);
      } else {
        await tg('answerCallbackQuery', { callback_query_id: cb.id, text: 'Deny failed: ' + (result.error || 'unknown') });
      }
    }
  }
}

// ---------- main loop ----------
async function main() {
  loadState();
  await dashLogin();
  console.log('bot started, watching', API_BASE);
  // telegram long polling
  (async () => {
    let offset;
    while (true) {
      const params = { timeout: 30 };
      if (offset) params.offset = offset;
      const data = await tg('getUpdates', params);
      if (data.ok) {
        for (const u of data.result) {
          offset = u.update_id + 1;
          try { await handleUpdate(u); } catch (e) { console.error('handleUpdate err', e); }
        }
      }
      await new Promise(r => setTimeout(r, 500));
    }
  })();
  // dashboard request polling
  (async () => {
    while (true) {
      try { await pollRequests(); } catch (e) { console.error('pollRequests err', e); }
      await new Promise(r => setTimeout(r, POLL_MS));
    }
  })();
}
main().catch(e => { console.error('fatal', e); process.exit(1); });
