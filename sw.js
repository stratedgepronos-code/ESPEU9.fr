// ═══ ESPE BASKET U9 — Service Worker v3.1 ═══
var SW_VERSION = '3.1';
var NOTIFICATION_TAG = 'espe-u9-notif';

// ── RÉCEPTION D'UN PUSH ──────────────────────────────────────────
self.addEventListener('push', function(event) {
    var title = '\uD83C\uDFC0 ESPE U9';
    var options = {
        body: 'Nouvelle notification',
        icon: 'https://espeu9.fr/images/logo-espe.png',
        badge: 'https://espeu9.fr/images/logo-espe.png',
        vibrate: [200, 100, 200],
        tag: NOTIFICATION_TAG,
        renotify: true,
        requireInteraction: false,
        data: { url: 'https://espeu9.fr/' }
    };

    var notifPromise;

    try {
        if (event.data) {
            var rawText = '';
            try { rawText = event.data.text(); } catch(e) {}

            if (rawText && rawText.length > 2) {
                try {
                    var data = JSON.parse(rawText);
                    if (data.title) title = data.title;
                    if (data.body) options.body = data.body;
                    if (data.icon) options.icon = data.icon;
                    if (data.badge) options.badge = data.badge;

                    // Tag basé sur le contenu pour éviter les doublons
                    options.tag = NOTIFICATION_TAG + '-' + (data.title || '').substring(0, 20).replace(/\s/g, '');

                    if (data.data && data.data.url) {
                        var targetUrl = data.data.url;
                        if (targetUrl.charAt(0) === '#') {
                            targetUrl = 'https://espeu9.fr/' + targetUrl;
                        } else if (targetUrl.indexOf('http') !== 0) {
                            targetUrl = 'https://espeu9.fr' + targetUrl;
                        }
                        options.data.url = targetUrl;
                    }
                } catch(jsonErr) {
                    options.body = rawText.substring(0, 200);
                    options.tag = NOTIFICATION_TAG + '-text';
                }
            }
        }

        // Fermer les anciennes notifications avant d'en montrer une nouvelle
        notifPromise = self.registration.getNotifications({ tag: options.tag })
            .then(function(existing) {
                existing.forEach(function(n) { n.close(); });
                return self.registration.showNotification(title, options);
            });
    } catch(outerErr) {
        // Fallback absolu : toujours montrer quelque chose
        notifPromise = self.registration.showNotification(title, options);
    }

    event.waitUntil(notifPromise);
});

// ── CLIC SUR NOTIFICATION → OUVRIR LE SITE ─────────────────────
self.addEventListener('notificationclick', function(event) {
    event.notification.close();

    var targetUrl = 'https://espeu9.fr/';
    if (event.notification.data && event.notification.data.url) {
        targetUrl = event.notification.data.url;
    }

    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then(function(windowClients) {
                for (var i = 0; i < windowClients.length; i++) {
                    var client = windowClients[i];
                    if (client.url.indexOf('espeu9.fr') !== -1) {
                        return client.focus().then(function(focusedClient) {
                            return focusedClient.navigate(targetUrl);
                        });
                    }
                }
                return clients.openWindow(targetUrl);
            })
    );
});

// ── CHANGEMENT DE SOUSCRIPTION PUSH (évite les notifs vides Chrome) ──
self.addEventListener('pushsubscriptionchange', function(event) {
    event.waitUntil(
        self.registration.pushManager.subscribe(event.oldSubscription.options)
            .then(function(newSub) {
                return fetch('https://espeu9.fr/api.php?action=push_subscribe', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        endpoint: newSub.endpoint,
                        keys: newSub.toJSON().keys
                    })
                });
            })
            .catch(function() {})
    );
});

// ── INSTALLATION: prise de contrôle immédiate ───────────────────
self.addEventListener('install', function(event) {
    self.skipWaiting();
});

// ── ACTIVATION: contrôler tous les onglets + nettoyer ────────────
self.addEventListener('activate', function(event) {
    event.waitUntil(
        Promise.all([
            self.clients.claim(),
            // Fermer toute notification résiduelle "fantôme"
            self.registration.getNotifications().then(function(notifications) {
                notifications.forEach(function(n) {
                    if (!n.title || n.title === '' || n.title === 'espeu9.fr') {
                        n.close();
                    }
                });
            })
        ])
    );
});
