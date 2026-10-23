// ETIPOS P2P Service Worker
// Version 1.0.0

const CACHE_NAME = 'etipos-p2p-v1';
const urlsToCache = [
  '/static/',
  '/static/index.html',
  '/static/p2p-send.html',
  '/static/p2p-receive.html',
  '/static/styles.css',
  '/static/app.js',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

// Install event - cache resources
self.addEventListener('install', (event) => {
  console.log('[Service Worker] Installing...');
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[Service Worker] Caching app shell');
        return cache.addAll(urlsToCache.map(url => new Request(url, {cache: 'reload'})));
      })
      .catch((err) => {
        console.error('[Service Worker] Cache failed:', err);
      })
  );
  
  // Force the waiting service worker to become the active service worker
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activating...');
  
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log('[Service Worker] Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  
  // Take control of all pages immediately
  return self.clients.claim();
});

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }
  
  // Skip WebSocket and chrome-extension requests
  if (url.protocol === 'ws:' || url.protocol === 'wss:' || url.protocol === 'chrome-extension:') {
    return;
  }
  
  // Skip API calls (they should always be fresh)
  if (url.pathname.startsWith('/transfer') || 
      url.pathname.startsWith('/download') || 
      url.pathname.startsWith('/health') ||
      url.pathname.startsWith('/scan')) {
    return event.respondWith(fetch(request));
  }
  
  // Network-first strategy for HTML pages (to get updates)
  if (request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // Clone the response before caching
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(request, responseToCache);
          });
          return response;
        })
        .catch(() => {
          // Fallback to cache if network fails
          return caches.match(request);
        })
    );
    return;
  }
  
  // Cache-first strategy for static assets
  event.respondWith(
    caches.match(request)
      .then((response) => {
        if (response) {
          return response;
        }
        
        return fetch(request).then((response) => {
          // Don't cache if not a valid response
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }
          
          // Clone the response before caching
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(request, responseToCache);
          });
          
          return response;
        });
      })
      .catch((err) => {
        console.error('[Service Worker] Fetch failed:', err);
      })
  );
});

// Handle Web Share Target (Android share menu)
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // Check if this is a share target request
  if (url.pathname === '/static/p2p-send.html' && event.request.method === 'POST') {
    event.respondWith(
      (async () => {
        const formData = await event.request.formData();
        const file = formData.get('file');
        
        if (file) {
          // Store the shared file in cache for the p2p-send page to retrieve
          const cache = await caches.open(CACHE_NAME);
          const fileData = {
            name: file.name,
            type: file.type,
            size: file.size,
            lastModified: file.lastModified,
            data: await file.arrayBuffer()
          };
          
          // Store in cache with a special key
          await cache.put(
            '/shared-file',
            new Response(JSON.stringify(fileData), {
              headers: { 'Content-Type': 'application/json' }
            })
          );
        }
        
        // Redirect to p2p-send page with a flag indicating a file was shared
        return Response.redirect('/static/p2p-send.html?shared=true', 303);
      })()
    );
  }
});

// Listen for messages from the page
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'CLEAR_CACHE') {
    event.waitUntil(
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => caches.delete(cacheName))
        );
      })
    );
  }
});

console.log('[Service Worker] Loaded');
