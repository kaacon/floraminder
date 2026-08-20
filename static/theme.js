(function () {
    const storageKey = 'floraminder-theme';

    function uporabiTemo(tema) {
        const temno = tema === 'dark';
        document.body.classList.toggle('dark-mode', temno);
        const preklopnik = document.getElementById('theme-switch');
        if (preklopnik) {
            preklopnik.checked = temno;
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        const shranjenaTema = localStorage.getItem(storageKey);
        const sistemskoTemno = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        uporabiTemo(shranjenaTema || (sistemskoTemno ? 'dark' : 'light'));

        const profilnaPovezava = document.querySelector('.sidebar-footer .user-profile-link');
        if (!profilnaPovezava) return;

        const vrstica = document.createElement('label');
        vrstica.className = 'theme-switch-row';
        vrstica.innerHTML = '<span>🌙 Temni način</span><input id="theme-switch" type="checkbox"><span class="theme-slider" aria-hidden="true"></span>';
        profilnaPovezava.before(vrstica);
        uporabiTemo(document.body.classList.contains('dark-mode') ? 'dark' : 'light');

        document.getElementById('theme-switch').addEventListener('change', function () {
            const novaTema = this.checked ? 'dark' : 'light';
            localStorage.setItem(storageKey, novaTema);
            uporabiTemo(novaTema);
        });
    });
}());
