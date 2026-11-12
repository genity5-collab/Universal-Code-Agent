"use strict";
const CACHE = "uca-shell-v1";
const SHELL = ["/", "/app.css", "/app.js", "/manifest.webmanifest", "/icons/icon-192.png", "/offline.html"];
self.addEventListener("install", (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener("activate", (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
const NEVER = /^\/(api|mcp|agent|auth|authorize|token|register|revoke|setup|healthz|\.well-known)(\/|$)/;
self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin || NEVER.test(u.pathname)) return;
  // network first so updates show immediately; fall back to cache offline
  e.respondWith(fetch(e.request).then((r) => { if (r.ok && SHELL.includes(u.pathname)) { const c = r.clone(); caches.open(CACHE).then((x) => x.put(e.request, c)); } return r; })
    .catch(() => caches.match(e.request).then((m) => m || (e.request.mode === "navigate" ? caches.match("/offline.html") : Response.error()))));
});
