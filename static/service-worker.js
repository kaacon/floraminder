// service-worker.js
// Sprejme push dogodek s strežnika in prikaže sistemsko obvestilo na PC-ju.

self.addEventListener('push', function (event) {
    let podatki = { title: 'Floraminder', body: 'Ena od tvojih rastlin te potrebuje 🌿' };
    if (event.data) {
        try {
            podatki = event.data.json();
        } catch (e) {
            podatki.body = event.data.text();
        }
    }

    event.waitUntil(
        self.registration.showNotification(podatki.title, {
            body: podatki.body,
            icon: '/static/logo.png',
            badge: '/static/logo.png',
            data: { url: podatki.url || '/dashboard' }
        })
    );
});

// Ob kliku na obvestilo odpri podrobnosti rastline oziroma dashboard.
self.addEventListener('notificationclick', function (event) {
    event.notification.close();
    const cilj = event.notification.data.url || '/dashboard';
    event.waitUntil(
        clients.matchAll({ type: 'window' }).then(function (clientList) {
            for (const client of clientList) {
                if (client.url.includes(cilj) && 'focus' in client) {
                    return client.focus();
                }
            }
            if (clients.openWindow) {
                return clients.openWindow(cilj);
            }
        })
    );
});
