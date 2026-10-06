/* Privacy regression for Vercel's page-vitals integration. No external calls. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../static/js/performance.js'), 'utf8');

function boot(pathname, existing = false) {
    const scripts = [], window = {};
    vm.runInNewContext(source, {
        window, location: {pathname, origin:'https://phishxai.vercel.app', search:'?url=private-token', hash:'#private-token'},
        document: {
            querySelector: () => existing ? {} : null,
            createElement: () => ({dataset:{}}),
            head: {append(script) { assert.equal(window.siq[0][0], 'beforeSend'); scripts.push(script); }}
        }
    });
    return {scripts, window};
}

test('page-vitals collector scrubs URL parameters before loading', () => {
    const {scripts, window} = boot('/');
    assert.equal(scripts.length, 1);
    assert.equal(scripts[0].src, '/_vercel/speed-insights/script.js');
    assert.equal(scripts[0].dataset.endpoint, '/_vercel/speed-insights/vitals');
    assert.equal(scripts[0].defer, true);
    const event = window.siq[0][1]({type:'vital', url:'https://phishxai.vercel.app/?url=private-token#secret', route:'/'});
    assert.equal(event.url,'https://phishxai.vercel.app/');
    assert.equal(event.type,'vital');
    assert.ok(!JSON.stringify(event).includes('private-token'));
});

test('API/report/unknown routes and repeated injection never collect', () => {
    for (const pathname of ['/api/scans/private-token','/download_report','/unknown']) {
        const {scripts,window}=boot(pathname);
        assert.equal(scripts.length,0);
        assert.equal(window.si,undefined);
    }
    assert.equal(boot('/',true).scripts.length,0);
});
