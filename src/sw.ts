// ETIPOS PWA Service Worker (TypeScript Source)
// Handles caching, background downloads, share targets, periodic checks, and push notifications

const sw: any = self;

const CACHE_NAME = 'etipos-v3-cache';
const ASSETS_TO_CACHE = [
  '/',
  '/static/index.html',
  '/static/styles.css',
  '/static/app.js',
  '/static/manifest.json',
  '/static/p2p-send.html',
  '/static/p2p-receive.html',
  '/static/vendor/webtorrent.min.js'
];

sw.addEventListener('install', (event: any) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    }).then(() => sw.skipWaiting())
  );
});

sw.addEventListener('activate', (event: any) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    }).then(() => sw.clients.claim())
  );
});

// Network-first cache fallback strategy
sw.addEventListener('fetch', (event: any) => {
  const url = new URL(event.request.url);

  // Skip caching API, dynamic downloads, and tunnel endpoints
  if (
    url.pathname.startsWith('/transfer') || 
    url.pathname.startsWith('/download') || 
    url.pathname.startsWith('/qr') || 
    url.pathname.startsWith('/health') ||
    url.pathname.startsWith('/tunnel-url') ||
    url.pathname.startsWith('/share-target')
  ) {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() => caches.match(event.request).then((res) => res || Response.error()))
  );
});

// Background Sync: Allows transfers or pings to complete even if network briefly dropped
sw.addEventListener('sync', (event: any) => {
  if (event.tag === 'etipos-sync-check') {
    event.waitUntil(
      fetch('/health').catch(() => console.log('Background sync ping pending recovery'))
    );
  }
});

// Periodic Background Sync (Supported in Android Chrome for installed PWAs)
sw.addEventListener('periodicsync', (event: any) => {
  if (event.tag === 'vault-check') {
    event.waitUntil(
      fetch('/health').catch(() => {})
    );
  }
});

// Push notification listener for file arrival alerts
sw.addEventListener('push', (event: any) => {
  const data = event.data ? event.data.json() : {};
  const title = data.title || 'ETIPOS Secure Relay';
  const options: any = {
    body: data.body || 'A file is ready for download in your vault.',
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    vibrate: [100, 50, 100],
    data: {
      url: data.url || '/'
    }
  };

  event.waitUntil(sw.registration.showNotification(title, options));
});

// Click notification opens download / portal
sw.addEventListener('notificationclick', (event: any) => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || '/';

  event.waitUntil(
    sw.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList: any[]) => {
      for (const client of clientList) {
        if ('focus' in client) {
          return client.focus();
        }
      }
      if (sw.clients.openWindow) {
        return sw.clients.openWindow(targetUrl);
      }
    })
  );
});

// Allow client app to send messages to trigger immediate skipWaiting
sw.addEventListener('message', (event: any) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    sw.skipWaiting();
  }
});
