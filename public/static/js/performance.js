/* Vercel's HTML integration. Collect page vitals, never scan inputs/results. */
(() => {
    const routes = new Set(['/', '/index', '/dashboard', '/crawler', '/apk_analyzer', '/pdf_analyzer', '/learn']);
    const route = location.pathname;
    if (!routes.has(route) || document.querySelector('script[data-phishx-vitals]')) return;
    window.si = window.si || function () { (window.siq = window.siq || []).push(arguments); };
    // Register before loading the collector, so query strings and fragments
    // (which may contain submitted links) cannot enter performance events.
    window.si('beforeSend', event => ({ ...event, url: location.origin + route, route }));
    const script = document.createElement('script');
    script.src = '/_vercel/speed-insights/script.js';
    script.defer = true;
    script.dataset.phishxVitals = 'true';
    script.dataset.route = route;
    script.dataset.endpoint = '/_vercel/speed-insights/vitals';
    document.head.append(script);
})();
