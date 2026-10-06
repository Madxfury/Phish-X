/* Keep initial, resized and restored navigation states consistent. */
(() => {
    const sidebar = document.getElementById('mainNavigation');
    const wrapper = document.querySelector('.main-wrapper');
    const button = document.querySelector('.toggle-sidebar');
    if (!sidebar || !wrapper || !button) return;
    const smallScreen = matchMedia('(max-width: 768px)');
    let desktopCollapsed = false;
    try { desktopCollapsed = sessionStorage.getItem('phishx.navCollapsed') === '1'; } catch {}
    function render(open) {
        const mobile = smallScreen.matches;
        sidebar.classList.toggle('nav-open', mobile && open);
        button.classList.toggle('nav-open', mobile && open);
        sidebar.classList.toggle('collapsed', !open);
        wrapper.classList.toggle('expanded', !open);
        button.classList.toggle('collapsed', !open);
        button.setAttribute('aria-expanded', String(open));
        sidebar.inert = mobile && !open;
        const icon = button.querySelector('i');
        icon.classList.toggle('fa-chevron-left', open);
        icon.classList.toggle('fa-chevron-right', !open);
    }
    function reset() { render(smallScreen.matches ? false : !desktopCollapsed); }
    window.toggleSidebar = () => {
        if (smallScreen.matches) render(!sidebar.classList.contains('nav-open'));
        else {
            desktopCollapsed = !desktopCollapsed;
            try { sessionStorage.setItem('phishx.navCollapsed', desktopCollapsed ? '1' : '0'); } catch {}
            render(!desktopCollapsed);
        }
    };
    smallScreen.addEventListener('change', reset);
    window.addEventListener('pageshow', reset);
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && smallScreen.matches) render(false);
    });
    reset();
})();
