/* Interface intro only; security analysis starts when the user submits a URL. */
(() => {
    const preloader = document.getElementById('hacker-preloader');
    const log = document.getElementById('preloader-log');
    const layout = document.querySelector('.layout-container');
    if (!preloader || !log || !layout) return;

    if (document.documentElement.classList.contains('skip-intro')) {
        preloader.remove();
        return;
    }
    try { sessionStorage.setItem('phishx.introSeen', '1'); } catch {}

    if (matchMedia('(prefers-reduced-motion: reduce)').matches) {
        preloader.remove();
        return;
    }

    document.body.classList.add('intro-active');
    layout.inert = true;
    let finished = false;
    let cleanupTimer;
    function decryptTitle() {
        const title = document.getElementById('decrypt-title');
        if (!title || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
        const text = title.textContent;
        const glyphs = '0123456789ABCDEF';
        const letters = [];
        title.setAttribute('aria-label', text);
        title.classList.add('is-decrypting');
        title.replaceChildren();
        text.split(' ').forEach((word, wordIndex) => {
            if (wordIndex) title.append(document.createTextNode(' '));
            const group = document.createElement('span');
            group.className = 'decrypt-word';
            group.setAttribute('aria-hidden', 'true');
            for (const char of word) {
                const cell = document.createElement('span');
                cell.className = 'decrypt-letter';
                const base = document.createElement('span');
                base.className = 'decrypt-letter-base';
                base.textContent = char;
                const animated = document.createElement('span');
                animated.className = 'decrypt-letter-value';
                animated.textContent = glyphs[Math.floor(Math.random() * glyphs.length)];
                cell.append(base, animated);
                group.append(cell);
                letters.push({ char, animated });
            }
            title.append(group);
        });
        // Each character reserves its final width, so scrambling cannot move the layout.
        let started;
        let lastUpdate = -40;
        const duration = 1600;
        function frame(now) {
            if (started === undefined) started = now;
            const elapsed = now - started;
            if (elapsed >= duration || matchMedia('(prefers-reduced-motion: reduce)').matches) {
                title.textContent = text;
                title.classList.remove('is-decrypting');
                return;
            }
            if (elapsed - lastUpdate >= 40) {
                const resolved = Math.floor(elapsed / duration * letters.length);
                letters.forEach(({ char, animated }, index) => {
                    animated.textContent = index < resolved ? char : glyphs[Math.floor(Math.random() * glyphs.length)];
                });
                lastUpdate = elapsed;
            }
            requestAnimationFrame(frame);
        }
        requestAnimationFrame(frame);
    }
    function finish() {
        if (finished) return;
        finished = true;
        clearTimeout(cleanupTimer);
        preloader.remove();
        layout.inert = false;
        document.body.classList.remove('intro-active');
    }
    function reveal() {
        const panel = preloader.querySelector('.right-panel');
        panel.addEventListener('transitionend', event => {
            if (event.target === panel && event.propertyName === 'transform') finish();
        });
        preloader.classList.add('animating-out');
        // Begin decrypting as the panels open, instead of waiting for cleanup.
        decryptTitle();
        // Cleanup still works if transitions are cancelled or disabled.
        const duration = parseFloat(getComputedStyle(preloader).getPropertyValue('--intro-exit-ms')) || 800;
        cleanupTimer = setTimeout(finish, duration + 150);
    }

    const lines = [
        { text: 'INITIALIZING PHISH-X AI INTERFACE...', type: 'info' },
        { text: 'LIVE WEBSITE INSPECTION · EVIDENCE REASONING', type: 'info' },
        { text: 'SERVICE AVAILABILITY IS SHOWN WITH EACH SCAN', type: 'warning' },
        { text: 'READY FOR URL INPUT', type: 'success' }
    ];
    const typedLines = lines.map(line => {
        const row = document.createElement('div');
        row.className = `terminal-line ${line.type}`;
        const space = document.createElement('span');
        space.className = 'terminal-line-space';
        space.setAttribute('aria-hidden', 'true');
        space.textContent = line.text;
        const typed = document.createElement('span');
        row.append(space, typed);
        log.append(row);
        return typed;
    });

    // Frame-based elapsed time avoids nested timer drift and reserves line height.
    const typingMs = 1050;
    const holdMs = 650;
    const totalChars = lines.reduce((count, line) => count + line.text.length, 0);
    let start;
    function animate(now) {
        if (start === undefined) start = now;
        const elapsed = now - start;
        let visibleChars = Math.floor(Math.min(elapsed / typingMs, 1) * totalChars);
        lines.forEach((line, index) => {
            typedLines[index].textContent = line.text.slice(0, Math.max(0, visibleChars));
            visibleChars -= line.text.length;
        });
        if (elapsed < typingMs + holdMs) requestAnimationFrame(animate);
        else reveal();
    }
    requestAnimationFrame(animate);
})();
