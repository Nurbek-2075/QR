/* Минимальный service worker: нужен для установки на телефон. Ничего не кэширует, данные всегда свежие. */
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',()=>{});
