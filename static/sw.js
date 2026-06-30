'use strict';

const CACHE_NAME   = 'synora-v2.1';
const STATIC_CACHE = 'synora-static-v2.1';

const PRECACHE = [
  '/',
  '/static/css/synora.css',
  '/static/js/synora.js',
  '/static/manifest.json',
  '/static/icons/icon-192.svg',
  '/static/icons/icon-512.svg',
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(STATIC_CACHE)
      .then(c => c.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== CACHE_NAME && k !== STATIC_CACHE)
            .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  if (
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/ws')   ||
    e.request.method !== 'GET'
  ) {
    return;
  }

  if (
    url.pathname.startsWith('/static/') ||
    url.hostname === 'fonts.googleapis.com' ||
    url.hostname === 'fonts.gstatic.com'
  ) {
    e.respondWith(
      caches.match(e.request).then(cached => {
        if (cached) return cached;
        return fetch(e.request).then(resp => {
          if (resp.ok) {
            const clone = resp.clone();
            caches.open(STATIC_CACHE).then(c => c.put(e.request, clone));
          }
          return resp;
        });
      })
    );
    return;
  }

  e.respondWith(
    fetch(e.request)
      .then(resp => {
        if (resp.ok && resp.type === 'basic') {
          const clone = resp.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        }
        return resp;
      })
      .catch(() => caches.match(e.request) || caches.match('/'))
  );
});

self.addEventListener('push', e => {
  let data = { title: 'Synora', body: 'New message', from: '' };
  try {
    data = e.data ? e.data.json() : data;
  } catch {}

  const title   = data.title || 'Synora';
  const options = {
    body:    data.body    || 'You have a new message',
    icon:    '/static/icons/icon-192.svg',
    badge:   '/static/icons/icon-192.svg',
    tag:     'synora-msg-' + (data.from || 'unknown'),
    renotify: true,
    silent:  false,
    data:    { url: '/', from: data.from || '' },
    actions: [
      { action: 'reply',   title: 'Reply'   },
      { action: 'dismiss', title: 'Dismiss' },
    ],
  };

  e.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  if (e.action === 'dismiss') return;

  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(wcs => {
      const existing = wcs.find(c => c.url.includes(self.location.origin));
      if (existing) {
        existing.focus();
        existing.postMessage({ type: 'notification_click', from: e.notification.data?.from });
        return;
      }
      return clients.openWindow('/');
    })
  );
});

self.addEventListener('sync', e => {
  if (e.tag === 'synora-msg-queue') {
    e.waitUntil(flushMsgQueue());
  }
});

async function flushMsgQueue() {
  const wcs = await clients.matchAll({ type: 'window' });
  wcs.forEach(c => c.postMessage({ type: 'sync_flush' }));
}