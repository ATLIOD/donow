document.addEventListener('htmx:configRequest', (event) => {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    event.detail.headers['X-CSRF-Token'] = csrfToken;
});
