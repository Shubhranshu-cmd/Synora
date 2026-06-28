'use strict';
const API = '';
let token = '', me = {}, ws = null, wsReady = false;
let contacts = [], currentPeer = null;
let typingTimer = null, typingActive = false;
let msgCache = {}, pubKeyCache = {};
let privKey = null;

let pc = null, localStream = null;
let callId = null, callType = null, callPeer = null, callDir = null;
let callTimerInterval = null, callSeconds = 0;
let isMuted = false, isVidOff = false, isSpeaker = false;
let pendingOffer = null, pendingCallType = null;

let wsRetryDelay = 1500;

let theme = localStorage.getItem('sn_theme') ||
  (window.matchMedia('(prefers-color-scheme:light)').matches ? 'light' : 'dark');
document.documentElement.setAttribute('data-theme', theme);

function toggleTheme() {
  theme = theme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('sn_theme', theme);
}

function toast(msg, type = '', duration = 3200) {
  const el = document.createElement('div');
  el.className = 'toast' + (type ? ' ' + type : '');
  el.textContent = msg;
  const c = document.getElementById('toast-container');
  c.appendChild(el);
  setTimeout(() => {
    el.classList.add('out');
    setTimeout(() => el.remove(), 300);
  }, duration);
}

async function genRSAKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
    true, ['encrypt','decrypt']
  );
}

const b64e = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64d = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

async function exportPub(k)  { return b64e(await crypto.subtle.exportKey('spki', k)); }
async function importPub(b64){ return crypto.subtle.importKey('spki', b64d(b64), { name:'RSA-OAEP', hash:'SHA-256' }, true, ['encrypt']); }
async function importPriv(b64){ return crypto.subtle.importKey('pkcs8', b64d(b64), { name:'RSA-OAEP', hash:'SHA-256' }, true, ['decrypt']); }
async function genAES()  { return crypto.subtle.generateKey({ name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']); }

async function encryptMsg(plain, recipPubB64) {
  const pub    = await importPub(recipPubB64);
  const aes    = await genAES();
  const aesRaw = await crypto.subtle.exportKey('raw', aes);
  const encKey = b64e(await crypto.subtle.encrypt({ name:'RSA-OAEP' }, pub, aesRaw));
  const iv     = crypto.getRandomValues(new Uint8Array(12));
  const ct     = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aes, new TextEncoder().encode(plain));
  return JSON.stringify({ k: encKey, iv: b64e(iv), ct: b64e(ct) });
}

async function decryptMsg(jsonStr) {
  if (!privKey) throw new Error('No private key');
  const o      = JSON.parse(jsonStr);
  const aesRaw = await crypto.subtle.decrypt({ name:'RSA-OAEP' }, privKey, b64d(o.k));
  const aes    = await crypto.subtle.importKey('raw', aesRaw, { name:'AES-GCM' }, false, ['decrypt']);
  const plain  = await crypto.subtle.decrypt({ name:'AES-GCM', iv: b64d(o.iv) }, aes, b64d(o.ct));
  return new TextDecoder().decode(plain);
}

async function storePrivKey(k) {
  localStorage.setItem('sn_pk', b64e(await crypto.subtle.exportKey('pkcs8', k)));
}

async function loadPrivKey() {
  const b = localStorage.getItem('sn_pk');
  if (!b) return null;
  try { return await importPriv(b); } catch { return null; }
}

function switchTab(t) {
  document.querySelectorAll('.auth-tab').forEach((b, i) =>
    b.classList.toggle('active', i === (t === 'login' ? 0 : 1))
  );
  $('login-form').style.display    = t === 'login'    ? '' : 'none';
  $('register-form').style.display = t === 'register' ? '' : 'none';
  $('auth-err').textContent = '';
}

async function doLogin() {
  const rawNum = $('l-num').value.replace(/\D/g, '');
  const pw     = $('l-pw').value;
  clearErr();
  if (!rawNum || !pw) return setErr('Please enter your Synora number and password');
  if (rawNum.length < 7 || rawNum.length > 10) return setErr('Synora number must be 7–10 digits');

  const btn = $('login-btn');
  btn.disabled = true; btn.textContent = 'Signing in…';
  try {
    const r = await apiReq('/api/login', { method: 'POST', body: { number: rawNum, password: pw } });
    privKey = await loadPrivKey();
    if (!privKey) {
      setErr('Private key not found on this device. Keys are stored locally and cannot be transferred. Please use the same device and browser you registered on, or create a new account.');
      btn.disabled = false; btn.textContent = 'Sign In';
      return;
    }
    initApp(r);
  } catch(e) {
    setErr(e.message);
  } finally {
    btn.disabled = false; btn.textContent = 'Sign In';
  }
}

async function doRegister() {
  const name = $('r-name').value.trim();
  const pw   = $('r-pw').value;
  const pw2  = $('r-pw2').value;
  clearErr();
  if (!name || !pw) return setErr('Please fill in all fields');
  if (name.length < 2)  return setErr('Name must be at least 2 characters');
  if (pw !== pw2)        return setErr('Passwords do not match');
  if (pw.length < 6)     return setErr('Password must be at least 6 characters');

  const btn = $('reg-btn');
  btn.disabled = true; btn.textContent = 'Generating encryption keys…';
  try {
    const pair   = await genRSAKeyPair();
    const pubB64 = await exportPub(pair.publicKey);
    await storePrivKey(pair.privateKey);
    privKey = pair.privateKey;
    btn.textContent = 'Creating account…';
    const r = await apiReq('/api/register', { method:'POST', body:{ name, password:pw, public_key:pubB64 } });
    toast(`Welcome, ${r.name}! Your Synora number is ${r.number} — save it!`, 'success', 8000);
    initApp(r);
  } catch(e) {
    setErr(e.message);
  } finally {
    btn.disabled = false; btn.textContent = 'Create Account';
  }
}

function setErr(m)  { $('auth-err').textContent = m; }
function clearErr() { $('auth-err').textContent = ''; }

function initApp(data) {
  token = data.token;
  me    = data;
  localStorage.setItem('sn_tok', token);
  localStorage.setItem('sn_me', JSON.stringify(me));
  $('auth-screen').style.display = 'none';
  $('app').style.display = 'block';
  const av = $('my-av');
  av.textContent = (me.name || '?')[0].toUpperCase();
  av.style.background = me.color || '#7C3AED';
  $('my-name-txt').textContent = me.name || '';
  showFooter(false);
  loadContacts();
  loadCallLogs();
  connectWS();
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
  }
}

async function restoreSession() {
  const t = localStorage.getItem('sn_tok');
  const m = localStorage.getItem('sn_me');
  if (!t || !m) { showFooter(true); return; }
  try {
    const resp = await fetch('/api/me', { headers: { 'Authorization': 'Bearer ' + t } });
    if (!resp.ok) throw new Error();
  } catch {
    localStorage.removeItem('sn_tok'); localStorage.removeItem('sn_me');
    showFooter(true); return;
  }
  token = t;
  try { me = JSON.parse(m); } catch { showFooter(true); return; }
  privKey = await loadPrivKey();
  if (!privKey) {
    localStorage.removeItem('sn_tok'); localStorage.removeItem('sn_me');
    showFooter(true); return;
  }
  try {
    const fresh = await apiReq('/api/me');
    me = { ...me, ...fresh };
    initApp(me);
  } catch {
    localStorage.removeItem('sn_tok'); localStorage.removeItem('sn_me');
    showFooter(true);
  }
}

function showFooter(show) {
  const el = document.querySelector('.footer-bar');
  if (el) el.style.display = show ? 'block' : 'none';
}

function doLogout() {
  if (!confirm('Sign out of Synora?')) return;
  token = ''; me = {};
  ['sn_tok','sn_me','sn_pk'].forEach(k => localStorage.removeItem(k));
  if (ws) { try { ws.close(); } catch {} }
  $('app').style.display = 'none';
  $('auth-screen').style.display = 'flex';
  currentPeer = null; contacts = [];
  $('clist').innerHTML = '';
  $('msgs').innerHTML = '';
  showFooter(true);
}

async function apiReq(path, opts = {}) {
  const h = { 'Content-Type': 'application/json' };
  if (token) h['Authorization'] = 'Bearer ' + token;
  const r = await fetch(path, {
    method: opts.method || 'GET',
    headers: h,
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.detail || 'Request failed');
  return d;
}

function connectWS() {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws/${token}`);
  ws.onopen    = () => { wsReady = true; wsRetryDelay = 1500; wsSend({ type:'ping' }); };
  ws.onmessage = e => { try { handleWS(JSON.parse(e.data)); } catch {} };
  ws.onclose   = () => {
    wsReady = false;
    setTimeout(connectWS, wsRetryDelay);
    wsRetryDelay = Math.min(wsRetryDelay * 1.6, 18000);
  };
  ws.onerror = () => { try { ws.close(); } catch {} };
}

setInterval(() => { if (wsReady) wsSend({ type:'ping' }); }, 25000);

function wsSend(d) {
  if (ws && wsReady) { try { ws.send(JSON.stringify(d)); } catch {} }
}

function handleWS(m) {
  const h = {
    message:       onInMsg,
    message_ack:   onAck,
    typing:        onTyping,
    read:          onRead,
    presence:      onPresence,
    call_offer:    onCallOffer,
    call_answer:   onCallAnswer,
    ice_candidate: onIce,
    call_reject:   onCallReject,
    call_end:      onCallEnd,
  };
  if (h[m.type]) h[m.type](m);
}

async function loadContacts() {
  try {
    contacts = await apiReq('/api/contacts');
    renderContacts(contacts);
  } catch(e) { console.warn('loadContacts:', e.message); }
}

function renderContacts(list) {
  const el = $('clist');
  if (!list.length) {
    el.innerHTML = `
      <div class="empty">
        <div class="ei"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>
        <p>No saved numbers yet.<br>Tap the + button to add someone.</p>
      </div>`;
    return;
  }
  el.innerHTML = list.map(c => {
    const init = (c.saved_name || '?')[0].toUpperCase();
    const isActive = currentPeer?.number === c.number;
    let preview = '';
    if (c.last_msg) {
      preview = (c.last_msg.startsWith('{') && c.last_msg.includes('"k"'))
        ? '🔒 Encrypted message' : esc(c.last_msg.substring(0,40));
    } else {
      preview = esc(c.status || '');
    }
    return `
    <div class="ci${isActive ? ' active' : ''}" onclick="openChat('${esc(c.number)}')" role="button" tabindex="0">
      <div class="av" style="background:${c.color||'#7C3AED'};color:#fff">
        ${init}
        ${c.online ? '<div class="online-dot"></div>' : ''}
      </div>
      <div class="ci-info">
        <div class="ci-name">${esc(c.saved_name)}</div>
        <div class="ci-last">${preview}</div>
      </div>
      <div class="ci-meta">
        <div class="ci-time">${fmtTime(c.last_ts)}</div>
        ${c.unread > 0 ? `<div class="ubadge">${c.unread > 99 ? '99+' : c.unread}</div>` : ''}
      </div>
    </div>`;
  }).join('');
}

let _lookupTimer = null;

function filterContacts(q) {
  const lq = q.trim().toLowerCase();
  if (!lq) { renderContacts(contacts); hideLookup(); return; }
  renderContacts(contacts.filter(c =>
    c.saved_name.toLowerCase().includes(lq) || c.number.includes(q.trim())
  ));
  const digits = q.replace(/\D/g,'');
  if (digits.length >= 1) {
    clearTimeout(_lookupTimer);
    _lookupTimer = setTimeout(() => doLookup(digits), 350);
  } else {
    hideLookup();
  }
}

async function doLookup(digits) {
  const drop = $('lookup-drop');
  try {
    const res = await apiReq('/api/lookup?q=' + encodeURIComponent(digits));
    if (!res.length) { hideLookup(); return; }
    drop.innerHTML = res.map(u => {
      const inCt = contacts.some(c => c.number === u.number);
      return `
      <div class="lookup-item" onmousedown="event.preventDefault()" onclick="selectLookup('${esc(u.number)}','${esc(u.name)}','${esc(u.color||'#7C3AED')}')">
        <div class="lookup-av" style="background:${esc(u.color||'#7C3AED')}">${(u.name||'?')[0].toUpperCase()}</div>
        <div class="lookup-info">
          <div class="lookup-name">${esc(u.name)}</div>
          <div class="lookup-sub">#${esc(u.number)} · ${inCt ? 'Already saved' : 'Tap to save'}</div>
        </div>
        ${u.online ? '<div style="width:9px;height:9px;border-radius:50%;background:var(--green2);flex-shrink:0"></div>' : ''}
      </div>`;
    }).join('');
    drop.style.display = 'block';
  } catch { hideLookup(); }
}

function hideLookup() {
  const d = $('lookup-drop');
  if (d) d.style.display = 'none';
}

function selectLookup(num, name, color) {
  hideLookup();
  $('srch-inp').value = '';
  renderContacts(contacts);
  const ex = contacts.find(c => c.number === num);
  if (ex) { openChat(num); return; }
  $('ac-num').value  = num;
  $('ac-name').value = name;
  $('ac-err').textContent = '';
  openModal('ac-modal');
  setTimeout(() => $('ac-name').focus(), 80);
}

function showAddContact() {
  $('ac-num').value = ''; $('ac-name').value = ''; $('ac-err').textContent = '';
  openModal('ac-modal');
  setTimeout(() => $('ac-num').focus(), 80);
}

async function addContact() {
  const rawNum = $('ac-num').value.replace(/\D/g,'');
  const name   = $('ac-name').value.trim();
  const errEl  = $('ac-err');
  errEl.textContent = '';
  if (!rawNum || !name) { errEl.textContent = 'Please fill in both fields'; return; }
  if (rawNum.length < 7 || rawNum.length > 10) { errEl.textContent = 'Synora number must be 7–10 digits'; return; }
  if (rawNum === me.number) { errEl.textContent = 'You cannot add yourself'; return; }

  const btn = document.querySelector('#ac-modal .btn-ok');
  btn.disabled = true; btn.textContent = 'Saving…';
  try {
    const c = await apiReq('/api/contacts', { method:'POST', body:{ number:rawNum, name } });
    const existing = contacts.findIndex(x => x.number === c.number);
    const full = { ...c, saved_name: name, online: 0, unread: 0 };
    if (existing >= 0) contacts[existing] = { ...contacts[existing], ...full };
    else contacts.unshift(full);
    renderContacts(contacts);
    closeModal('ac-modal');
    openChat(c.number);
    toast(`${name} added to your contacts`, 'success');
  } catch(e) {
    errEl.textContent = e.message;
  } finally {
    btn.disabled = false; btn.textContent = 'Save';
  }
}

function openModal(id)  { $(id).classList.add('show'); }
function closeModal(id) { $(id).classList.remove('show'); }

async function openChat(number) {
  const c = contacts.find(x => x.number === number);
  if (!c) { toast('Contact not found. Please save their number first.'); return; }
  currentPeer = c;
  $('no-chat').style.display = 'none';
  const ac = $('active-chat');
  ac.style.display = 'flex';

  const av = $('ch-av');
  av.textContent = (c.saved_name||'?')[0].toUpperCase();
  av.style.background = c.color || '#7C3AED';
  av.style.color = '#fff';

  $('ch-name').textContent = c.saved_name;
  $('ch-number').textContent = '#' + c.number;
  updatePeerStatus(c);

  if (window.innerWidth <= 750) $('sidebar').classList.add('hidden');
  renderContacts(contacts);
  await loadMessages(number);
  $('msg-inp').focus();
  wsSend({ type:'read', from:number });
  $('srch-res').classList.remove('show');
  if (c.unread) { c.unread = 0; renderContacts(contacts); }
}

function updatePeerStatus(c) {
  const el = $('ch-st');
  if (!el) return;
  if (c.online) {
    el.textContent = 'online';
    el.className = 'peer-st online';
  } else {
    el.textContent = c.last_seen ? 'last seen ' + fmtTime(c.last_seen) : '';
    el.className = 'peer-st';
  }
}

async function loadMessages(num) {
  const area = $('msgs');
  area.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text3);font-size:13px">Loading…</div>';
  msgOldestTs[num] = null;
  try {
    const msgs = await apiReq(`/api/messages/${num}`);
    msgCache[num] = msgs;
    if (msgs.length > 0) msgOldestTs[num] = msgs[0].ts;
    const wrap = $('load-more-wrap');
    if (wrap) wrap.style.display = msgs.length >= 60 ? 'block' : 'none';
    await renderMessages(msgs);
  } catch(e) {
    area.innerHTML = `<div style="text-align:center;padding:20px;color:var(--red);font-size:13px">${esc(e.message)}</div>`;
  }
}

const msgOldestTs = {};

async function loadOlderMessages() {
  if (!currentPeer) return;
  const num = currentPeer.number;
  const oldest = msgOldestTs[num];
  const btn = $('load-more-btn');
  if (!oldest || !btn) return;
  btn.disabled = true;
  btn.textContent = 'Loading…';
  try {
    const older = await apiReq(`/api/messages/${num}?before=${encodeURIComponent(oldest)}`);
    if (!older.length) {
      $('load-more-wrap').style.display = 'none';
      return;
    }
    msgOldestTs[num] = older[0].ts;
    msgCache[num] = [...older, ...(msgCache[num] || [])];
    if (older.length < 60) $('load-more-wrap').style.display = 'none';

    const area = $('msgs');
    const prevH = area.scrollHeight;
    await renderMessages(msgCache[num], false);
    area.scrollTop = area.scrollHeight - prevH;
  } catch(e) {
    toast('Could not load older messages: ' + e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Load older messages'; }
  }
}

async function renderMessages(msgs, scrollToBottom = true) {
  const area = $('msgs');
  if (!msgs.length) {
    area.innerHTML = '<div style="text-align:center;padding:48px;color:var(--text3);font-size:13px;line-height:1.8">🔒 End-to-end encrypted<br>No messages yet<br><span style="font-size:11px">Say hello!</span></div>';
    return;
  }
  const frags = [];
  let lastDate = '';
  for (const m of msgs) {
    let content = m.content;
    if (m.deleted) {
      const out = m.sender === me.number;
      frags.push(`<div class="mr ${out?'out':'in'}" id="msg-${m.msg_id}">
        <div class="bub"><div class="bub-txt msg-deleted-pill">🚫 Message deleted</div></div></div>`);
      continue;
    }
    try {
      if (privKey && content && content.startsWith('{') && content.includes('"k"')) {
        content = await decryptMsg(content);
      }
    } catch { content = '🔒 Encrypted'; }
    const d = m.ts ? m.ts.split('T')[0] : '';
    if (d !== lastDate) {
      frags.push(`<div class="dsep">${fmtDate(m.ts)}</div>`);
      lastDate = d;
    }
    const out = m.sender === me.number;
    frags.push(`
      <div class="mr ${out?'out':'in'}" id="msg-${m.msg_id}"
           oncontextmenu="showMsgCtx(event,'${esc(m.msg_id)}','${out?'out':'in'}')"
           ontouchstart="startMsgLongPress(event,'${esc(m.msg_id)}','${out?'out':'in'}')">
        <div class="bub">
          <div class="bub-txt">${esc(content)}</div>
          <div class="bub-foot">
            <span class="bub-time">${fmtClock(m.ts)}</span>
            ${out ? `<span class="bub-st ${m.status||''}">${stSvg(m.status)}</span>` : ''}
          </div>
        </div>
      </div>`);
  }
  area.innerHTML = frags.join('');
  if (scrollToBottom) area.scrollTop = area.scrollHeight;
}

let _ctxTimeout = null;

function showMsgCtx(e, msgId, dir) {
  e.preventDefault();
  closeMsgCtx();
  const menu = document.createElement('div');
  menu.className = 'msg-ctx-menu';
  menu.id = 'msg-ctx';
  const items = [];
  items.push(`<div class="msg-ctx-item" onclick="copyMsgText('${msgId}')">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
      <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
    </svg> Copy text</div>`);
  if (dir === 'out') {
    items.push(`<div class="msg-ctx-item danger" onclick="deleteMsg('${msgId}')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
        <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/>
        <path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
      </svg> Delete for everyone</div>`);
  } else {
    items.push(`<div class="msg-ctx-item danger" onclick="openReportModal(null,'${msgId}')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
        <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/>
        <line x1="4" y1="22" x2="4" y2="15"/>
      </svg> Report message</div>`);
  }
  menu.innerHTML = items.join('');
  document.body.appendChild(menu);

  const x = Math.min(e.clientX || (e.touches?.[0]?.clientX || 0), window.innerWidth - 180);
  const y = Math.min(e.clientY || (e.touches?.[0]?.clientY || 0), window.innerHeight - 100);
  menu.style.left = x + 'px';
  menu.style.top  = y + 'px';

  document.addEventListener('click', closeMsgCtx, { once: true });
}

function closeMsgCtx() {
  const el = document.getElementById('msg-ctx');
  if (el) el.remove();
}

function startMsgLongPress(e, msgId, dir) {
  _ctxTimeout = setTimeout(() => showMsgCtx(e, msgId, dir), 600);
}
document.addEventListener('touchend', () => clearTimeout(_ctxTimeout));
document.addEventListener('touchmove', () => clearTimeout(_ctxTimeout));

function copyMsgText(msgId) {
  const el = document.getElementById('msg-' + msgId);
  if (!el) return;
  const txt = el.querySelector('.bub-txt')?.textContent || '';
  navigator.clipboard?.writeText(txt).then(() => toast('Copied to clipboard'));
  closeMsgCtx();
}

async function deleteMsg(msgId) {
  closeMsgCtx();
  if (!confirm('Delete this message for everyone? This cannot be undone.')) return;
  try {
    await apiReq(`/api/messages/${msgId}`, { method: 'DELETE' });
    if (currentPeer && msgCache[currentPeer.number]) {
      const m = msgCache[currentPeer.number].find(x => x.msg_id === msgId);
      if (m) m.deleted = 1;
      await renderMessages(msgCache[currentPeer.number]);
    }
    toast('Message deleted');
  } catch(e) { toast('Could not delete: ' + e.message, 'error'); }
}


function stSvg(s) {
  if (s === 'read')      return '<span style="color:var(--accent2)">✓✓</span>';
  if (s === 'delivered') return '<span>✓✓</span>';
  return '<span>✓</span>';
}

async function sendMessage() {
  const inp  = $('msg-inp');
  const text = inp.value.trim();
  if (!text || !currentPeer) return;
  inp.value = ''; inp.style.height = 'auto';

  let pub = pubKeyCache[currentPeer.number];
  if (!pub) {
    try {
      const u = await apiReq(`/api/user/${currentPeer.number}`);
      if (!u.public_key) throw new Error('This contact has no encryption key registered');
      pub = u.public_key;
      pubKeyCache[currentPeer.number] = pub;
    } catch(e) {
      toast('Could not fetch contact key: ' + e.message, 'error'); return;
    }
  }

  let encrypted;
  try { encrypted = await encryptMsg(text, pub); }
  catch(e) { toast('Encryption failed: ' + e.message, 'error'); return; }

  const tmpId = 'tmp-' + Date.now();
  const tmpMsg = { msg_id:tmpId, sender:me.number, receiver:currentPeer.number, content:text, status:'sent', ts:new Date().toISOString() };
  if (!msgCache[currentPeer.number]) msgCache[currentPeer.number] = [];
  msgCache[currentPeer.number].push(tmpMsg);
  await renderMessages(msgCache[currentPeer.number]);

  const ci = contacts.find(c => c.number === currentPeer.number);
  if (ci) { ci.last_msg = text; ci.last_ts = tmpMsg.ts; renderContacts(contacts); }

  stopTyping();
  wsSend({ type:'message', to:currentPeer.number, content:encrypted, from_name:me.name, _tmpId:tmpId });
}

function handleKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

function handleTyping() {
  const inp = $('msg-inp');
  inp.style.height = 'auto';
  inp.style.height = Math.min(inp.scrollHeight, 120) + 'px';
  if (!currentPeer) return;
  if (!typingActive) { typingActive = true; wsSend({ type:'typing', to:currentPeer.number, typing:true }); }
  clearTimeout(typingTimer);
  typingTimer = setTimeout(stopTyping, 2500);
}

function stopTyping() {
  if (!typingActive) return;
  typingActive = false;
  if (currentPeer) wsSend({ type:'typing', to:currentPeer.number, typing:false });
}

async function onInMsg(msg) {
  let plain = '🔒 Encrypted';
  try {
    if (privKey && msg.content && msg.content.startsWith('{') && msg.content.includes('"k"'))
      plain = await decryptMsg(msg.content);
  } catch {}

  const c = contacts.find(x => x.number === msg.from);
  if (c) { c.last_msg = plain; c.last_ts = msg.ts; }

  if (currentPeer?.number !== msg.from) {
    showNotif(c ? c.saved_name : (msg.from_name || msg.from), plain);
    if (c) { c.unread = (c.unread || 0) + 1; }
    renderContacts(contacts);
  } else {
    if (!msgCache[msg.from]) msgCache[msg.from] = [];
    msgCache[msg.from].push({
      ...msg, msg_id: msg.msg_id || ('rx-' + Date.now()),
      sender: msg.from, receiver: me.number, content: plain
    });
    await renderMessages(msgCache[msg.from]);
    wsSend({ type:'read', from:msg.from });
    renderContacts(contacts);
  }
}

function onAck(msg) {
  if (!currentPeer) return;
  const msgs = msgCache[currentPeer.number] || [];
  const tmp  = msgs.find(m => m.msg_id && m.msg_id.startsWith('tmp-'));
  if (tmp) {
    tmp.msg_id  = msg.msg_id;
    tmp.status  = msg.status;
    tmp.ts      = msg.ts;
    renderMessages(msgs);
  }
}

function onTyping(msg) {
  if (currentPeer?.number !== msg.from) return;
  const ind = $('typ-ind');
  if (msg.typing) {
    ind.innerHTML = `<span class="tdots"><span></span><span></span><span></span></span>
      <span style="font-size:12px;color:var(--text3)">${esc(currentPeer.saved_name)} is typing…</span>`;
  } else {
    ind.innerHTML = '';
  }
}

function onRead(msg) {
  if (!currentPeer || currentPeer.number !== msg.by) return;
  const msgs = msgCache[currentPeer.number] || [];
  msgs.filter(m => m.sender === me.number).forEach(m => m.status = 'read');
  renderMessages(msgs);
}

function onPresence(msg) {
  const c = contacts.find(x => x.number === msg.number);
  if (c) { c.online = msg.online; c.last_seen = msg.last_seen; renderContacts(contacts); }
  if (currentPeer?.number === msg.number)
    updatePeerStatus({ ...currentPeer, online: msg.online, last_seen: msg.last_seen });
}

function closeChatMobile() {
  $('sidebar').classList.remove('hidden');
  $('no-chat').style.display = 'flex';
  $('active-chat').style.display = 'none';
  currentPeer = null;
  renderContacts(contacts);
}

async function doSearch() {
  const el = $('srch-res');
  if (el.classList.contains('show')) { el.classList.remove('show'); el.innerHTML = ''; return; }
  const q = prompt('Search messages:');
  if (!q || !q.trim()) return;
  try {
    const results = await apiReq('/api/search?q=' + encodeURIComponent(q.trim()));
    el.innerHTML = results.length
      ? results.map(r => `
        <div class="sri" onclick="jumpMsg('${r.msg_id}')">
          <span class="sr-sndr">${r.sender === me.number ? 'You' : esc(currentPeer?.saved_name || r.sender)}</span>
          ${r.score ? `<span class="sr-sc">${Math.round(r.score * 100)}%</span>` : ''}
          <div class="sr-prev">${esc((r.content || '').substring(0,90))}</div>
        </div>`).join('')
      : '<div style="padding:12px 14px;color:var(--text3);font-size:13px">No results found</div>';
    el.classList.add('show');
  } catch(e) { toast('Search error: ' + e.message, 'error'); }
}

function jumpMsg(id) {
  const el = document.getElementById('msg-' + id);
  if (el) {
    el.scrollIntoView({ behavior:'smooth', block:'center' });
    el.style.outline = '2px solid var(--accent2)';
    el.style.borderRadius = '14px';
    setTimeout(() => { el.style.outline = ''; el.style.borderRadius = ''; }, 2200);
  }
  $('srch-res').classList.remove('show');
}

async function loadCallLogs() {
  try {
    const logs = await apiReq('/api/call-logs');
    const el   = $('calls-list');
    if (!logs.length) {
      el.innerHTML = `
        <div class="empty">
          <div class="ei"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12a19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 3.6 1.27h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.96a16 16 0 0 0 6.12 6.12l.96-.86a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg></div>
          <p>No call history yet.</p>
        </div>`;
      return;
    }
    el.innerHTML = logs.map(l => {
      const out  = l.caller === me.number;
      const peer = out ? l.callee : l.caller;
      const typeIcon = l.call_type === 'video' ? svgVideoSm() : svgPhoneSm();
      const dirLabel = out ? 'Outgoing' : 'Incoming';
      const statusLabel = l.status === 'ended' ? fmtDur(l.duration)
                        : l.status === 'rejected' ? 'Declined'
                        : l.status === 'missed'   ? 'Missed'
                        : l.status;
      const isMissed = !out && (l.status === 'missed' || l.status === 'rejected');
      return `
      <div class="call-item">
        <div class="av" style="background:${l.color||'#7C3AED'};color:#fff;width:46px;height:46px;font-size:17px">
          ${(l.name||'?')[0].toUpperCase()}
        </div>
        <div class="call-info">
          <div class="call-name">${esc(l.name||'Unknown')}</div>
          <div class="call-meta">
            <span>${out ? '↗' : '↙'}</span>
            ${typeIcon}
            <span class="${isMissed?'missed':''}">${dirLabel} · ${statusLabel} · ${fmtTime(l.ts)}</span>
          </div>
        </div>
        <button class="call-icon-btn" onclick="callFromLog('${esc(peer)}','${esc(l.call_type)}')" title="Call back">
          ${l.call_type==='video' ? svgVideoSm() : svgPhoneSm()}
        </button>
      </div>`;
    }).join('');
  } catch(e) { console.warn('loadCallLogs:', e.message); }
}

function callFromLog(num, type) {
  const c = contacts.find(x => x.number === num);
  if (c) { currentPeer = c; startCall(type); }
  else toast('Contact not in your saved numbers');
}

function switchMainTab(t) {
  document.querySelectorAll('.tab-btn').forEach((b, i) =>
    b.classList.toggle('active', i === (t === 'chats' ? 0 : 1))
  );
  $('clist').style.display       = t === 'chats' ? '' : 'none';
  $('calls-list').style.display  = t === 'calls' ? '' : 'none';
  if (t === 'calls') loadCallLogs();
}

const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun2.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' },
];

async function startCall(type) {
  if (!currentPeer) return;
  if (callId) { toast('You are already in a call'); return; }
  callType = type; callPeer = currentPeer; callDir = 'out';
  callId = crypto.randomUUID();
  showCallScr(callPeer, type, 'Calling…');
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video: type==='video' });
    if (type === 'video') {
      $('local-video').srcObject = localStream;
      $('local-video').style.display = 'block';
      $('btn-vid').classList.add('show');
    }
    pc = mkPC();
    localStream.getTracks().forEach(t => pc.addTrack(t, localStream));
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    wsSend({ type:'call_offer', to:callPeer.number, call_id:callId, call_type:type, sdp:offer.sdp });
  } catch(e) {
    toast('Mic/Camera permission denied: ' + e.message, 'error');
    endCallClean();
  }
}

async function onCallOffer(msg) {
  if (callId) { wsSend({ type:'call_reject', to:msg.from, call_id:msg.call_id }); return; }
  pendingOffer    = msg;
  pendingCallType = msg.call_type;
  const c = contacts.find(x => x.number === msg.from);
  showIncCall(c ? c.saved_name : (msg.from_name || msg.from), msg.call_type, c?.color, msg.from);
  playRing();
}

async function acceptCall() {
  stopRing(); hideIncCall();
  const msg = pendingOffer;
  if (!msg) return;
  const c = contacts.find(x => x.number === msg.from);
  callType = pendingCallType;
  callPeer = c || { number:msg.from, saved_name:msg.from, color:'#7C3AED' };
  callDir  = 'in';
  callId   = msg.call_id;
  showCallScr(callPeer, callType, 'Connecting…');
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video: callType==='video' });
    if (callType === 'video') {
      $('local-video').srcObject = localStream;
      $('local-video').style.display = 'block';
      $('btn-vid').classList.add('show');
    }
    pc = mkPC();
    localStream.getTracks().forEach(t => pc.addTrack(t, localStream));
    await pc.setRemoteDescription({ type:'offer', sdp:msg.sdp });
    const ans = await pc.createAnswer();
    await pc.setLocalDescription(ans);
    wsSend({ type:'call_answer', to:msg.from, call_id:callId, sdp:ans.sdp });
  } catch(e) {
    toast('Mic/Camera error: ' + e.message, 'error');
    endCallClean();
  }
  pendingOffer = null;
}

function rejectCall() {
  stopRing(); hideIncCall();
  if (pendingOffer) wsSend({ type:'call_reject', to:pendingOffer.from, call_id:pendingOffer.call_id });
  pendingOffer = null;
}

async function onCallAnswer(msg) {
  if (!pc || !msg.sdp) return;
  try { await pc.setRemoteDescription({ type:'answer', sdp:msg.sdp }); } catch {}
}

async function onIce(msg) {
  if (!pc || !msg.candidate) return;
  try { await pc.addIceCandidate(msg.candidate); } catch {}
}

function onCallReject() {
  $('call-st').textContent = 'Call declined';
  $('call-st').style.display = 'block';
  setTimeout(endCallClean, 2000);
}

function onCallEnd() {
  $('call-st').textContent = 'Call ended';
  $('call-st').style.display = 'block';
  setTimeout(endCallClean, 1500);
}

function mkPC() {
  const p = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  p.onicecandidate = e => {
    if (e.candidate && callPeer)
      wsSend({ type:'ice_candidate', to:callPeer.number, call_id:callId, candidate:e.candidate });
  };
  p.ontrack = e => {
    const rv = $('remote-video');
    rv.srcObject = e.streams[0];
    if (callType === 'video') rv.style.display = 'block';
  };
  p.onconnectionstatechange = () => {
    if (p.connectionState === 'connected') {
      $('call-screen').classList.add('connected');
      $('call-st').style.display = 'none';
      startCallTmr();
    }
    if (['failed','disconnected'].includes(p.connectionState)) {
      $('call-st').textContent = 'Connection lost';
      $('call-st').style.display = 'block';
    }
  };
  return p;
}

function endCall() {
  wsSend({ type:'call_end', to:callPeer?.number, call_id:callId, duration:callSeconds });
  endCallClean();
}

function endCallClean() {
  stopCallTmr();
  if (pc) { try { pc.close(); } catch {} pc = null; }
  if (localStream) { localStream.getTracks().forEach(t => t.stop()); localStream = null; }
  const rv = $('remote-video');
  const lv = $('local-video');
  if (rv) { rv.srcObject = null; rv.style.display = 'none'; }
  if (lv) { lv.srcObject = null; lv.style.display = 'none'; }
  const cs = $('call-screen');
  cs.classList.remove('active','connected');
  callId = null; callType = null; callPeer = null; callDir = null;
  callSeconds = 0; isMuted = false; isVidOff = false; isSpeaker = false;
  const muteBtn = $('btn-mute');
  if (muteBtn) { muteBtn.classList.remove('active','danger'); muteBtn.querySelector('.cg-label').textContent = 'Mute'; }
  const vidBtn = $('btn-vid');
  if (vidBtn) { vidBtn.classList.remove('active','show'); vidBtn.querySelector('.cg-label').textContent = 'Camera'; }
  const spkBtn = $('btn-spk');
  if (spkBtn) spkBtn.classList.remove('active');
  loadCallLogs();
}

function showCallScr(peer, type, status) {
  const cs = $('call-screen');
  const av = $('call-av');
  av.textContent = (peer.saved_name||'?')[0].toUpperCase();
  av.style.background = peer.color || '#7C3AED';
  $('call-nm').textContent   = peer.saved_name;
  $('call-num-lbl').textContent = '#' + peer.number;
  $('call-st').textContent   = status;
  $('call-st').style.display = 'block';
  $('call-tmr-top').textContent = '00:00';
  cs.classList.remove('connected');
  cs.classList.add('active');
}

function showIncCall(name, type, color, number) {
  const av = $('ic-av');
  av.textContent = (name||'?')[0].toUpperCase();
  av.style.background = color || '#7C3AED';
  $('ic-nm').textContent  = name;
  $('ic-num').textContent = '#' + (number || '');
  $('ic-tp').textContent  = (type === 'video' ? 'Video call' : 'Voice call') + ' · Synora';
  $('inc-call').classList.add('active');
}

function hideIncCall() { $('inc-call').classList.remove('active'); }

function toggleMute() {
  isMuted = !isMuted;
  if (localStream) localStream.getAudioTracks().forEach(t => t.enabled = !isMuted);
  const btn = $('btn-mute');
  btn.classList.toggle('active', isMuted);
  btn.classList.toggle('danger', isMuted);
  btn.querySelector('.cg-label').textContent = isMuted ? 'Unmute' : 'Mute';
  btn.querySelector('.cg-icon').innerHTML = isMuted ? svgMicOff() : svgMicOn();
}

function toggleVid() {
  isVidOff = !isVidOff;
  if (localStream) localStream.getVideoTracks().forEach(t => t.enabled = !isVidOff);
  const btn = $('btn-vid');
  btn.classList.toggle('active', isVidOff);
  btn.querySelector('.cg-label').textContent = isVidOff ? 'Cam off' : 'Camera';
  btn.querySelector('.cg-icon').innerHTML = isVidOff ? svgCamOff() : svgCamOn();
}

function toggleSpeaker() {
  isSpeaker = !isSpeaker;
  const btn = $('btn-spk');
  if (btn) btn.classList.toggle('active', isSpeaker);
  toast(isSpeaker ? 'Speaker mode — use device controls' : 'Earpiece mode — use device controls');
}

function showCallMore() { $('call-more-sheet').classList.add('active'); }
function hideCallMore() { $('call-more-sheet').classList.remove('active'); }

function startCallTmr() {
  callSeconds = 0;
  callTimerInterval = setInterval(() => {
    callSeconds++;
    const m = String(Math.floor(callSeconds / 60)).padStart(2,'0');
    const s = String(callSeconds % 60).padStart(2,'0');
    const timeStr = m + ':' + s;
    $('call-tmr-top').textContent = timeStr;
  }, 1000);
}

function stopCallTmr() { clearInterval(callTimerInterval); callTimerInterval = null; }

let audioCtx = null, ringInterval = null;

function playRing() {
  try {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const ring = () => {
      const o = audioCtx.createOscillator();
      const g = audioCtx.createGain();
      o.connect(g); g.connect(audioCtx.destination);
      o.frequency.value = 480; o.type = 'sine';
      g.gain.setValueAtTime(0, audioCtx.currentTime);
      g.gain.linearRampToValueAtTime(0.28, audioCtx.currentTime + 0.05);
      g.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.9);
      o.start(); o.stop(audioCtx.currentTime + 0.9);
    };
    ring();
    ringInterval = setInterval(ring, 1400);
  } catch {}
}

function stopRing() {
  clearInterval(ringInterval); ringInterval = null;
  if (audioCtx) { try { audioCtx.close(); } catch {} audioCtx = null; }
}

function showNotif(name, body) {
  if (Notification.permission === 'granted') {
    new Notification(`✦ ${name}`, { body, icon: '/static/icons/icon-192.png' });
  }
}

function showProfile() {
  $('prof-body').innerHTML = `
    <div class="prof-big-av" style="background:${me.color||'#7C3AED'};color:#fff">
      ${(me.name||'?')[0].toUpperCase()}
    </div>
    <div class="prof-num">${esc(me.number||'')}</div>
    <div class="prof-nm">${esc(me.name||'')}</div>
    <div class="icard">
      <label>Synora Number</label>
      <p style="font-size:22px;font-weight:800;color:var(--accent2);letter-spacing:3px">${esc(me.number||'')}</p>
      <p style="font-size:12px;color:var(--text3);margin-top:6px">Share this number so others can find you on Synora</p>
    </div>
    <div class="icard">
      <label>Status</label>
      <div class="icard-edit">
        <input id="status-edit" value="${esc(me.status||'Hey there! I am using Synora.')}" maxlength="120">
        <button class="icard-save" onclick="saveStatus()">Save</button>
      </div>
    </div>
    <div class="icard">
      <label>Security</label>
      <p style="color:var(--green2);font-weight:600">🔒 RSA-2048 + AES-256-GCM</p>
      <p style="font-size:12px;color:var(--text3);margin-top:4px">End-to-end encrypted · Keys never leave your device</p>
    </div>
    <div class="icard">
      <label>Private Key</label>
      <p style="font-size:12px;color:var(--text3);margin-bottom:10px">Back up or restore your encryption key</p>
      <button class="btn-primary" style="max-width:320px;background:var(--panel3);box-shadow:none;color:var(--text)" onclick="openKeyBackupModal()">
        🔑 Manage Key Backup
      </button>
    </div>
    <div class="icard">
      <label>Notifications</label>
      <button class="btn-primary" style="max-width:320px;background:var(--panel3);box-shadow:none;color:var(--text)" onclick="subscribePush()">
        🔔 Enable Push Notifications
      </button>
    </div>
    <button class="btn-primary" style="max-width:320px;margin-top:6px;background:var(--panel3);box-shadow:none;color:var(--text)" onclick="doLogout()">Sign Out</button>`;
  $('prof-panel').classList.add('active');
}

async function saveStatus() {
  const val = ($('status-edit')?.value || '').trim();
  try {
    await apiReq('/api/me/status', { method:'PUT', body:{ status:val } });
    me.status = val;
    localStorage.setItem('sn_me', JSON.stringify(me));
    toast('Status updated', 'success');
  } catch(e) { toast('Could not save: ' + e.message, 'error'); }
}

function closeProfile()  { $('prof-panel').classList.remove('active'); }

function showPeerProfile() {
  if (!currentPeer) return;
  const c = currentPeer;
  $('prof-body').innerHTML = `
    <div class="prof-big-av" style="background:${c.color||'#7C3AED'};color:#fff">
      ${(c.saved_name||'?')[0].toUpperCase()}
    </div>
    <div class="prof-num">${esc(c.number)}</div>
    <div class="prof-nm">${esc(c.saved_name)}</div>
    <div class="icard"><label>Synora Number</label>
      <p style="font-size:22px;font-weight:800;color:var(--accent2);letter-spacing:3px">${esc(c.number)}</p>
    </div>
    <div class="icard"><label>Status</label><p>${esc(c.status||'No status set')}</p></div>
    <div class="icard"><label>Presence</label>
      <p style="color:${c.online?'var(--green2)':'var(--text2)'}">
        ${c.online ? '🟢 Online now' : '⚫ Last seen ' + fmtTime(c.last_seen)}
      </p>
    </div>
    <button class="btn-primary" style="max-width:320px;margin-top:4px" onclick="startCall('voice');closeProfile()">
      Voice Call
    </button>
    <button class="btn-primary" style="max-width:320px;margin-top:8px;background:var(--panel2);color:var(--text);box-shadow:none" onclick="startCall('video');closeProfile()">
      Video Call
    </button>
    <button class="btn-primary" style="max-width:320px;margin-top:8px;background:transparent;color:var(--red);box-shadow:none;border:1px solid rgba(239,68,68,0.3)" onclick="removeContact()">
      Remove Contact
    </button>
    <button class="btn-primary" style="max-width:320px;margin-top:8px;background:transparent;color:var(--text3);box-shadow:none;border:1px solid var(--border)" onclick="openReportModal('${esc(c.number)}');closeProfile()">
      🚨 Report User
    </button>`;
  $('prof-panel').classList.add('active');
}

async function removeContact() {
  if (!currentPeer) return;
  if (!confirm(`Remove ${currentPeer.saved_name} from your contacts?`)) return;
  try {
    await apiReq(`/api/contacts/${currentPeer.number}`, { method:'DELETE' });
    contacts = contacts.filter(c => c.number !== currentPeer.number);
    closeChatMobile();
    closeProfile();
    renderContacts(contacts);
    toast(`${currentPeer.saved_name} removed`);
  } catch(e) { toast('Could not remove: ' + e.message, 'error'); }
}

function $(id) { return document.getElementById(id); }

function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function fmtTime(ts) {
  if (!ts) return '';
  const d   = new Date(ts.includes('T') ? ts : ts + 'Z');
  const now = new Date();
  if (isNaN(d)) return '';
  if (d.toDateString() === now.toDateString())
    return d.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
  const diff = (now - d) / 864e5;
  if (diff < 7) return ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][d.getDay()];
  return d.toLocaleDateString([], { day:'2-digit', month:'2-digit' });
}

function fmtDate(ts) {
  if (!ts) return '';
  const d   = new Date(ts.includes('T') ? ts : ts + 'Z');
  const now = new Date();
  if (isNaN(d)) return '';
  if (d.toDateString() === now.toDateString()) return 'Today';
  const yest = new Date(now); yest.setDate(now.getDate()-1);
  if (d.toDateString() === yest.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], { day:'numeric', month:'long', year:'numeric' });
}

function fmtClock(ts) {
  if (!ts) return '';
  const d = new Date(ts.includes('T') ? ts : ts + 'Z');
  if (isNaN(d)) return '';
  return d.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
}

function fmtDur(s) {
  if (!s) return '0:00';
  return Math.floor(s/60) + ':' + String(s%60).padStart(2,'0');
}

function svgPhoneSm() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12a19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 3.6 1.27h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.96a16 16 0 0 0 6.12 6.12l.96-.86a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>'; }
function svgVideoSm() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>'; }
function svgMicOn()   { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg>'; }
function svgMicOff()  { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22"><line x1="1" y1="1" x2="23" y2="23"/><path d="M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6"/><path d="M17 16.95A7 7 0 0 1 5 12v-2m14 0v2a7 7 0 0 1-.11 1.23"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg>'; }
function svgCamOn()   { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>'; }
function svgCamOff()  { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22"><line x1="1" y1="1" x2="23" y2="23"/><path d="M21 21H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h3m3-3h6l2 3h2a2 2 0 0 1 2 2v9.34"/><line x1="8" y1="13" x2="8.01" y2="13"/></svg>'; }

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    closeModal('ac-modal');
    closeProfile();
    hideCallMore();
    $('srch-res').classList.remove('show');
  }
});

document.getElementById('l-pw')?.addEventListener('keydown',   e => { if(e.key==='Enter') doLogin(); });
document.getElementById('l-num')?.addEventListener('keydown',  e => { if(e.key==='Enter') doLogin(); });
document.getElementById('ac-num')?.addEventListener('keydown', e => { if(e.key==='Enter') $('ac-name').focus(); });
document.getElementById('ac-name')?.addEventListener('keydown',e => { if(e.key==='Enter') addContact(); });
document.getElementById('r-pw2')?.addEventListener('keydown',  e => { if(e.key==='Enter') doRegister(); });


function openKeyBackupModal() {
  closeProfile();
  document.getElementById('key-backup-modal').classList.add('active');
  switchKbTab('export');
}

function switchKbTab(tab) {
  ['export','import','server'].forEach(t => {
    const el = document.getElementById('kb-' + t);
    if (el) el.style.display = t === tab ? 'block' : 'none';
  });
  document.querySelectorAll('.kb-tab').forEach((b, i) => {
    b.classList.toggle('active', ['export','import','server'][i] === tab);
  });
  const errEl = document.getElementById('kb-err');
  if (errEl) errEl.textContent = '';
}

async function deriveKeyFromPw(password, salt) {
  const enc   = new TextEncoder();
  const base  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt','decrypt']
  );
}

async function exportKeyBackup() {
  const pw  = document.getElementById('kb-export-pw')?.value || '';
  const err = document.getElementById('kb-err');
  if (!pw) { if (err) err.textContent = 'Please enter your password'; return; }
  if (!privKey) { if (err) err.textContent = 'No private key in memory'; return; }
  try {
    const pkcs8  = await crypto.subtle.exportKey('pkcs8', privKey);
    const salt   = crypto.getRandomValues(new Uint8Array(16));
    const iv     = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await deriveKeyFromPw(pw, salt);
    const ct     = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, pkcs8);

    const payload = JSON.stringify({
      v:    1,
      salt: b64e(salt),
      iv:   b64e(iv),
      ct:   b64e(ct),
      alg:  'PBKDF2-200k-AES-256-GCM',
    });

    const blob = new Blob([payload], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `synora-key-${me.number}-${Date.now()}.synkey`;
    a.click();
    URL.revokeObjectURL(url);
    toast('Key backup downloaded — store it somewhere safe!', 'success', 5000);
    if (err) err.textContent = '';
  } catch(e) { if (err) err.textContent = 'Export failed: ' + e.message; }
}

async function importKeyBackup() {
  const fileInp = document.getElementById('kb-import-file');
  const pw      = document.getElementById('kb-import-pw')?.value || '';
  const err     = document.getElementById('kb-err');
  if (!fileInp?.files?.[0]) { if (err) err.textContent = 'Please select a .synkey file'; return; }
  if (!pw) { if (err) err.textContent = 'Please enter the backup password'; return; }
  try {
    const text    = await fileInp.files[0].text();
    const payload = JSON.parse(text);
    const salt    = b64d(payload.salt);
    const iv      = b64d(payload.iv);
    const ct      = b64d(payload.ct);
    const aesKey  = await deriveKeyFromPw(pw, salt);
    const pkcs8   = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, aesKey, ct);
    const newKey  = await importPriv(b64e(pkcs8));
    privKey = newKey;
    await storePrivKey(newKey);
    toast('Private key restored successfully!', 'success', 5000);
    closeModal('key-backup-modal');
    if (err) err.textContent = '';
  } catch(e) {
    if (err) err.textContent = 'Import failed — wrong password or corrupt file';
  }
}

async function uploadKeyBackup() {
  const pw  = document.getElementById('kb-server-pw')?.value || '';
  const st  = document.getElementById('kb-server-status');
  const err = document.getElementById('kb-err');
  if (!pw) { if (err) err.textContent = 'Please enter your password'; return; }
  if (!privKey) { if (err) err.textContent = 'No private key in memory'; return; }
  if (st) st.textContent = 'Encrypting…';
  try {
    const pkcs8   = await crypto.subtle.exportKey('pkcs8', privKey);
    const salt    = crypto.getRandomValues(new Uint8Array(16));
    const iv      = crypto.getRandomValues(new Uint8Array(12));
    const aesKey  = await deriveKeyFromPw(pw, salt);
    const ct      = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, pkcs8);
    const payload = JSON.stringify({ v:1, salt:b64e(salt), iv:b64e(iv), ct:b64e(ct), alg:'PBKDF2-200k-AES-256-GCM' });
    if (st) st.textContent = 'Uploading…';
    await apiReq('/api/me/key-backup', { method:'PUT', body:{ key_backup: payload } });
    toast('Key backup saved to server', 'success');
    if (st) st.textContent = '✅ Backed up to server';
    if (err) err.textContent = '';
  } catch(e) {
    if (err) err.textContent = 'Upload failed: ' + e.message;
    if (st) st.textContent = '';
  }
}

async function downloadKeyFromServer() {
  const pw  = document.getElementById('kb-server-pw')?.value || '';
  const err = document.getElementById('kb-err');
  if (!pw) { if (err) err.textContent = 'Please enter your password'; return; }
  try {
    const r = await apiReq('/api/me/key-backup');
    if (!r.key_backup) throw new Error('No backup found on server');
    const payload = JSON.parse(r.key_backup);
    const salt    = b64d(payload.salt);
    const iv      = b64d(payload.iv);
    const ct      = b64d(payload.ct);
    const aesKey  = await deriveKeyFromPw(pw, salt);
    const pkcs8   = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, aesKey, ct);
    const newKey  = await importPriv(b64e(pkcs8));
    privKey = newKey;
    await storePrivKey(newKey);
    toast('Key restored from server backup!', 'success', 5000);
    closeModal('key-backup-modal');
    if (err) err.textContent = '';
  } catch(e) {
    if (err) err.textContent = 'Restore failed — wrong password or no backup found';
  }
}


function openReportModal(num, msgId) {
  const target = num || currentPeer?.number || '';
  document.getElementById('report-target-num').value   = target;
  document.getElementById('report-target-msgid').value = msgId || '';
  document.getElementById('report-err').textContent = '';
  document.querySelectorAll('input[name="rep-reason"]').forEach(r => r.checked = false);
  document.getElementById('report-details').value = '';
  document.getElementById('report-modal').classList.add('active');
}

async function submitReport() {
  const targetNum = document.getElementById('report-target-num').value;
  const msgId     = document.getElementById('report-target-msgid').value;
  const reason    = document.querySelector('input[name="rep-reason"]:checked')?.value;
  const details   = document.getElementById('report-details').value.trim();
  const err       = document.getElementById('report-err');

  if (!reason) { if (err) err.textContent = 'Please select a reason'; return; }
  if (!targetNum) { if (err) err.textContent = 'No user to report'; return; }

  try {
    await apiReq('/api/report', {
      method: 'POST',
      body: { reported_number: targetNum, reason, details, msg_id: msgId || undefined }
    });
    toast('Report submitted. Thank you.', 'success');
    closeModal('report-modal');
  } catch(e) {
    if (err) err.textContent = 'Could not submit report: ' + e.message;
  }
}

async function subscribePush() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    toast('Push notifications not supported in this browser', 'error');
    return;
  }
  const perm = await Notification.requestPermission();
  if (perm !== 'granted') { toast('Notification permission denied'); return; }

  try {
    let applicationServerKey = null;
    try {
      const keyResp = await fetch('/api/push/vapid-public-key');
      if (keyResp.ok) {
        const keyData = await keyResp.json();
        if (keyData.publicKey) {
          const raw = keyData.publicKey
            .replace(/-----.*?-----/g, '')
            .replace(/\s+/g, '');
          const binary = atob(raw.replace(/-/g,'+').replace(/_/g,'/'));
          applicationServerKey = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) {
            applicationServerKey[i] = binary.charCodeAt(i);
          }
        }
      }
    } catch(e) {
      console.warn('[push] Could not fetch VAPID key:', e);
    }

    const reg = await navigator.serviceWorker.ready;
    const subscribeOptions = { userVisibleOnly: true };
    if (applicationServerKey) subscribeOptions.applicationServerKey = applicationServerKey;

    const sub = await reg.pushManager.subscribe(subscribeOptions).catch(e => {
      console.warn('[push] subscribe error:', e);
      return null;
    });

    if (sub) {
      await apiReq('/api/push/subscribe', { method:'POST', body:{ subscription: sub.toJSON() } });
      localStorage.setItem('sn_push', '1');
      toast('Push notifications enabled!', 'success');
    } else {
      toast('Push notification setup failed — check browser permissions', 'error');
    }
  } catch(e) {
    console.warn('[push]', e);
    toast('Push notification setup failed: ' + e.message, 'error');
  }
}

(function() {
  let banner = null;
  function ensureBanner() {
    if (!banner) {
      banner = document.createElement('div');
      banner.className = 'offline-banner';
      banner.textContent = '⚠️  No internet connection — messages will send when you reconnect';
      document.body.prepend(banner);
    }
    return banner;
  }
  window.addEventListener('offline', () => ensureBanner().classList.add('show'));
  window.addEventListener('online',  () => { if (banner) banner.classList.remove('show'); });
  if (!navigator.onLine) ensureBanner().classList.add('show');
})();

restoreSession();