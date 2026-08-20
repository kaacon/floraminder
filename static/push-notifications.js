// push-notifications.js
// Poveže gumb "Omogoči push obvestila" z registracijo service workerja
// in naročnino na Web Push, ki jo nato pošlje na strežnik (/push/subscribe).

function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

async function omogociPushObvestila() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        alert('Ta brskalnik ne podpira push obvestil.');
        return;
    }

    try {
        const dovoljenje = await Notification.requestPermission();
        if (dovoljenje !== 'granted') {
            alert('Push obvestila niso dovoljena. Lahko jih omogočiš kasneje v nastavitvah brskalnika.');
            return;
        }

        const registracija = await navigator.serviceWorker.register('/static/service-worker.js');

        const odgovor = await fetch('/push/public-key');
        const { publicKey } = await odgovor.json();

        if (!publicKey) {
            alert('Strežnik še nima nastavljenih VAPID ključev za push obvestila (glej notifications.py).');
            return;
        }

        const subscription = await registracija.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlBase64ToUint8Array(publicKey)
        });

        await fetch('/push/subscribe', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
            },
            body: JSON.stringify(subscription)
        });

        const gumb = document.getElementById('btn-omogoci-push');
        if (gumb) {
            gumb.textContent = '✅ Push obvestila omogočena';
            gumb.disabled = true;
        }
    } catch (napaka) {
        console.error('Napaka pri omogočanju push obvestil:', napaka);
        alert('Prišlo je do napake pri omogočanju push obvestil.');
    }
}

document.addEventListener('DOMContentLoaded', function () {
    const gumb = document.getElementById('btn-omogoci-push');
    if (gumb) {
        gumb.addEventListener('click', omogociPushObvestila);
    }
});