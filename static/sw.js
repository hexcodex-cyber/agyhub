/* Home-screen shell only. Chat and login stay on the network. */
var CACHE = "agyhub-shell-1";
var SHELL = ["/icon-192.png", "/icon-512.png", "/apple-touch-icon.png", "/manifest.webmanifest"];

self.addEventListener("install", function (event) {
  event.waitUntil(caches.open(CACHE).then(function (cache) {
    return cache.addAll(SHELL);
  }).then(function () { return self.skipWaiting(); }));
});

self.addEventListener("activate", function (event) {
  event.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (key) { return key !== CACHE; }).map(function (key) {
      return caches.delete(key);
    }));
  }).then(function () { return self.clients.claim(); }));
});

self.addEventListener("fetch", function (event) {
  var url = new URL(event.request.url);
  if (event.request.method !== "GET" || SHELL.indexOf(url.pathname) === -1) return;
  event.respondWith(caches.open(CACHE).then(function (cache) {
    return fetch(event.request).then(function (res) {
      if (res.ok) cache.put(event.request, res.clone());
      return res;
    }).catch(function () {
      return cache.match(event.request).then(function (hit) {
        return hit || Response.error();
      });
    });
  }));
});
