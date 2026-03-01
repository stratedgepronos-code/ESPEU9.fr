// ═══ ESPE BASKET U9 — Service Worker v2.0 ═══
// Gère les notifications push et le clic sur notification
var SW_VERSION = '2.0';

// ── RÉCEPTION D'UN PUSH ──────────────────────────────────────────
self.addEventListener('push', function(event) {
    // Valeurs par défaut (au cas où le payload est vide ou corrompu)
    var title = '🏀 ESPE U9';
    var options = {
        body: 'Nouvelle notification',
        icon: 'https://espeu9.fr/images/logo-espe.png',
        badge: 'https://espeu9.fr/images/logo-espe.png',
        vibrate: [200, 100, 200],
        tag: 'espe-u9-' + Date.now(),
        renotify: true,
        requireInteraction: false,
        data: { url: 'https://espeu9.fr/' }
    };

    // Essayer de lire le payload chiffré
    if (event.data) {
        try {
            var data = event.data.json();
            if (data.title) title = data.title;
            if (data.body) options.body = data.body;
            if (data.icon) options.icon = data.icon;
            if (data.badge) options.badge = data.badge;

            // Construire l'URL de redirection
            if (data.data && data.data.url) {
                var targetUrl = data.data.url;
                if (targetUrl.charAt(0) === '#') {
                    targetUrl = 'https://espeu9.fr/' + targetUrl;
                } else if (targetUrl.indexOf('http') !== 0) {
                    targetUrl = 'https://espeu9.fr' + targetUrl;
                }
                options.data.url = targetUrl;
            }
        } catch (e) {
            // Si le JSON échoue, essayer en texte brut
            try {
                var txt = event.data.text();
                if (txt && txt.length > 0) {
                    options.body = txt.substring(0, 200);
                }
            } catch (e2) {
                // Garder les valeurs par défaut
            }
        }
    }

    // TOUJOURS afficher une notification
    // Sans ça, Chrome affiche "Appuyez pour copier l'URL"
    event.waitUntil(
        self.registration.showNotification(title, options)
    );
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
                // Chercher un onglet déjà ouvert sur espeu9.fr
                for (var i = 0; i < windowClients.length; i++) {
                    var client = windowClients[i];
                    if (client.url.indexOf('espeu9.fr') !== -1) {
                        return client.focus().then(function(focusedClient) {
                            return focusedClient.navigate(targetUrl);
                        });
                    }
                }
                // Sinon, ouvrir un nouvel onglet
                return clients.openWindow(targetUrl);
            })
    );
});

// ── INSTALLATION: prise de contrôle immédiate ───────────────────
self.addEventListener('install', function(event) {
    self.skipWaiting();
});

// ── ACTIVATION: contrôler tous les onglets existants ────────────
self.addEventListener('activate', function(event) {
    event.waitUntil(self.clients.claim());
});
