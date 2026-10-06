/* Targeted result behavior for the original Flask/Jinja scanner UI. */
'use strict';
let currentResult = null;
let isScanning = false;
const savedStateKey = 'phishx.scanState.v1';
let viewState = {view:'none'};
function readState() {
    try { return JSON.parse(sessionStorage.getItem(savedStateKey)) || {}; } catch { return {}; }
}
function saveState() {
    const state = {...viewState, url:element('urlInput').value, bulk:Array.from(document.querySelectorAll('.bulk-url-line'), input => input.value), scrollY:window.scrollY};
    try { sessionStorage.setItem(savedStateKey, JSON.stringify(state)); } catch { /* Storage can be disabled or full; scans remain usable. */ }
}
const scanSocket = window.PHISHX_SOCKETIO && window.io ? io({transports: ['polling', 'websocket'], timeout: 5000}) : null;
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
const element = id => document.getElementById(id);
const observed = value => value === null || value === undefined ? 'Unavailable' : esc(value);
const dateText = value => value ? new Date(value).toLocaleString() : '';
const list = values => `<ul class="evidence-list">${values.map(v => `<li>${v}</li>`).join('')}</ul>`;
const card = (title, body, wide = false) => `<article class="evidence-card${wide ? ' wide' : ''}"><h3>${esc(title)}</h3>${body}</article>`;

function findingDetail(item) {
    if (item.id === 'intel.virustotal') {
        const detail = item.detail;
        const counts = ['malicious','suspicious','harmless','undetected','total'];
        return `<dl class="evidence-values">${counts.map(key => `<div><dt>${esc(key)}</dt><dd>${observed(detail[key])}</dd></div>`).join('')}</dl><p class="scan-note">Vendor classifications; see Threat intelligence for individual detections and report date.</p>`;
    }
    const detail = item.detail;
    if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
        return `<dl class="technical-details">${Object.entries(detail).map(([key,value]) => `<dt>${esc(key.replaceAll('_',' '))}</dt><dd>${esc(typeof value === 'object' ? JSON.stringify(value, null, 2) : value)}</dd>`).join('')}</dl>`;
    }
    return `<p>${esc(Array.isArray(detail) ? detail.map(value => value && typeof value === 'object' ? JSON.stringify(value, null, 2) : value).join('\n') : detail)}</p>`;
}

async function requestJSON(url, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), body === undefined ? 20000 : 300000);
    let response;
    let data;
    try {
        response = await fetch(url, body === undefined ? {signal:controller.signal} : {method: 'POST', signal:controller.signal, headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)});
        try { data = await response.json(); } catch { throw new Error('Server returned an unreadable response. Please retry.'); }
    } catch(error) {
        if (error.name === 'AbortError') throw new Error('The server response timed out. Please retry.');
        throw error;
    } finally { clearTimeout(timer); }
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
    return data;
}

function reportButtons(enabled) {
    element('downloadReportBtn').disabled = !enabled;
    element('downloadReportBtnInline').disabled = !enabled;
    element('rescanLiveBtn').disabled = !enabled;
}

function showLoading(message = 'Scanning the website. Actual stages appear as they complete.') {
    element('loadingIndicator').style.display = 'flex';
    element('resultsContainer').style.display = 'none';
    element('resultsSection').style.display = 'block';
    element('historySection').style.display = 'none';
    element('bulkResultsSection').style.display = 'none';
    element('scanEvidence').hidden = true;
    element('scanProgressText').textContent = message;
    element('liveProgress').replaceChildren();
    reportButtons(false);
}

function hideLoading() {
    element('loadingIndicator').style.display = 'none';
    element('resultsContainer').style.display = 'block';
}

if (scanSocket) scanSocket.on('scan_stage', step => {
    if (!isScanning) return;
    const line = document.createElement('li');
    line.textContent = `${step.stage}: ${step.status} — ${step.detail}`;
    element('liveProgress').append(line);
    element('scanProgressText').textContent = step.stage;
});

function formatResult(data) {
    hideLoading();
    if (!data || data.error || typeof data.risk_score !== 'number') {
        currentResult = null;
        element('verdictIcon').className = 'verdict-icon medium-risk';
        element('verdictIcon').innerHTML = '<i class="fas fa-question-circle" aria-hidden="true"></i>';
        element('verdictTitle').textContent = 'Scan could not complete';
        element('verdictText').textContent = data?.error || 'Unexpected scan response. Please retry.';
        element('riskScore').textContent = '';
        element('scanMeta').textContent = '';
        element('scanEvidence').hidden = true;
        reportButtons(false);
        return;
    }
    currentResult = data;
    document.querySelector('.container').classList.add('has-analysis');
    const unknown = data.assessment === 'UNKNOWN';
    const color = data.risk_score >= 60 ? 'high-risk' : data.assessment !== 'SAFE' ? 'medium-risk' : 'safe';
    element('verdictIcon').className = `verdict-icon ${color}`;
    const icon = data.risk_score >= 60 ? 'harmful' : data.assessment === 'SAFE' ? 'safe' : 'suspicious';
    element('verdictIcon').innerHTML = unknown ? '<i class="fas fa-question-circle" aria-hidden="true"></i>' : `<img src="/static/images/verdicts/${icon}.png?v=clean-1" alt="" width="64" height="64">`;
    element('verdictTitle').textContent = unknown ? 'Insufficient evidence for a verdict' : `${data.assessment} · observed risk`;
    element('verdictText').textContent = data.recommendation;
    element('riskScore').innerHTML = `<strong>${data.risk_score}<small>/100</small></strong><progress value="${data.risk_score}" max="100" aria-label="Observed risk score"></progress>`;
    element('scanMeta').textContent = `${data.state.replaceAll('_',' ')} · ${data.cached ? 'Stored scan from ' : 'Scanned '}${dateText(data.timestamp)} · ${data.cached ? 'cached evidence' : `${(data.duration_ms / 1000).toFixed(1)}s`}`;
    reportButtons(Boolean(data.scan_id));
    renderEvidence(data);
    viewState = {view:'single', result:data};
    saveState();
}

function renderEvidence(data) {
    const f = data.features, surface = data.attack_surface, ai = data.ai, content = f.content;
    const findings = data.evidence.filter(item => item.points > 0);
    const reasons = findings.length ? list(findings.map(item => `<strong>${esc(item.label)}</strong> <span class="evidence-points">+${item.points}</span>${findingDetail(item)}<small>${esc(item.id)} · ${esc(item.source)} · ${esc(item.kind)}</small>`)) : '<p>No scoring indicators were observed in the available evidence. Missing evidence does not establish safety.</p>';
    let aiBody = `<p class="status-note">AI ${esc(ai.status.replaceAll('_',' '))}</p><p>${esc(ai.reason || 'AI result unavailable.')}</p>`;
    if (ai.status === 'completed') aiBody = `<p><strong>${esc(ai.assessment)}</strong> · ${Math.round(ai.confidence * 100)}% self-reported confidence</p><p class="scan-note">${esc(ai.confidence_note)} · ${esc(ai.provider)} / ${esc(ai.model)}</p>` +
        list(ai.key_reasons.map(reason => `${esc(reason.interpretation)}<small>Evidence: ${reason.evidence_ids.map(esc).join(', ')}</small>`)) + `<p>${esc(ai.recommended_action)}</p>` + list(ai.limitations.map(esc));
    const dna = `<p class="scan-note">Evidence points / dimension cap. These are heuristic contributions, not percentages or probabilities.</p>` + data.phishing_dna.map(d => `<div class="dna-row"><span>${esc(d.label)}</span><strong>${d.available ? `${d.points}/${d.cap}` : 'Unavailable'}</strong>${d.available ? `<progress max="${d.cap}" value="${d.points}" aria-label="${esc(d.label)} evidence points"></progress>` : ''}<small>${d.evidence_ids.map(esc).join(', ') || 'No evidence available'}</small></div>`).join('');
    const surfaceRows = [['Forms',surface.forms],['Password fields',surface.password_fields],['Payment fields (sample)',surface.payment_fields],['Scripts',surface.scripts],['Iframes (sample)',surface.iframes],['Hidden inputs',surface.hidden_inputs],['Referenced resources (sample)',surface.resources],['Observed HTTP redirects',surface.redirects],['External domains (sample)',surface.external_domains?.length],['Sensitive form destination warnings',surface.suspicious_destinations?.length]];
    const snapshot = `<dl class="surface-grid">${surfaceRows.map(([key,value]) => `<div><dt>${esc(key)}</dt><dd>${observed(value)}</dd></div>`).join('')}</dl><p class="scan-note">${esc(surface.note)}</p>` + (surface.external_domains?.length ? `<details><summary>External domains</summary>${list(surface.external_domains.map(esc))}</details>` : '') + (surface.suspicious_destinations?.length ? `<details><summary>Form destination evidence</summary>${list(surface.suspicious_destinations.map(d => esc(d.url)))}</details>` : '') + (surface.trackers?.length ? `<details><summary>Recognized resource patterns</summary>${list(surface.trackers.map(t => `${esc(t.label)}: ${esc(t.url)}`))}</details>` : '');
    const vt = f.virus_total;
    const intelligence = `<p>VirusTotal: <strong>${esc(vt.status)}</strong> ${esc(vt.error || vt.reason || '')}</p>` + (typeof vt.total === 'number' ? `<dl class="surface-grid">${['malicious','suspicious','harmless','undetected','total'].map(k => `<div><dt>${esc(k)}</dt><dd>${vt[k]}</dd></div>`).join('')}</dl><p class="scan-note">Analysis: ${vt.analysis_date ? dateText(vt.analysis_date * 1000) : 'date unavailable'} · ${esc(vt.source || '')}</p>` : '<p class="scan-note">No completed engine counts available.</p>') +
        (vt.vendors?.length ? list(vt.vendors.map(v => `${esc(v.vendor)}: ${esc(v.category)} — ${esc(v.result)}`)) : '') + `<p>Google Safe Browsing: ${esc(f.google_safe_browsing.status)}</p>` + (f.google_safe_browsing.matches?.length ? list(f.google_safe_browsing.matches.map(m => esc(m.threat_type))) : '');
    const http = f.http;
    const technical = `<dl class="technical-details"><dt>HTTP fetch</dt><dd>${esc(http.status)} ${esc(http.reason || '')}</dd><dt>HTTP status</dt><dd>${observed(http.status_code)}</dd><dt>Final URL</dt><dd>${observed(http.final_url)}</dd><dt>Title</dt><dd>${observed(content.title)}</dd><dt>Public DNS addresses</dt><dd>${esc(f.dns.addresses?.join(', ') || 'Unavailable')}</dd><dt>Registration age</dt><dd>${observed(f.domain_age.domain_age_days)}${f.domain_age.domain_age_days != null ? ' days' : ''} · ${esc(f.domain_age.registered_domain || f.domain.registered_domain)} · ${esc(f.domain_age.status)}</dd><dt>TLS</dt><dd>${esc(f.certificate.status)} · ${esc(f.certificate.tls_version || f.certificate.reason || '')}</dd></dl>` +
        `<details><summary>Security headers</summary>${list(Object.entries(f.security_headers).map(([name,value]) => `${esc(name)}: ${value ? esc(value) : http.status_code ? 'not present' : 'unavailable'}`))}</details>` +
        (f.redirection.chain?.length ? `<details><summary>Redirect chain</summary>${list(f.redirection.chain.map(hop => `${hop.status_code}: ${esc(hop.from)} → ${esc(hop.to)}`))}</details>` : '') +
        (content.script_fetches?.length ? `<details><summary>Downloaded script coverage</summary>${list(content.script_fetches.map(s => `${esc(s.url)}: ${esc(s.status)} ${esc(s.reason || '')}`))}</details>` : '');
    const timeline = `<ol class="evidence-timeline">${data.timeline.map(step => `<li><div class="timeline-entry-heading"><strong>${esc(step.stage)}</strong><span class="stage-status" data-status="${esc(step.status)}">${esc(step.status.replaceAll('_', ' '))}</span><time>${(step.elapsed_ms / 1000).toFixed(1)}s</time></div><p>${esc(step.detail)}</p></li>`).join('')}</ol>`;
    const missing = data.unavailable.length ? list(data.unavailable.map(item => `<strong>${esc(item.source)}</strong>: ${esc(item.status)} · ${esc(item.reason)}`)) : '<p>All configured evidence stages completed.</p>';
    element('scanEvidence').innerHTML = card('AI evidence reasoning',aiBody,true) + card('Evidence and scoring',reasons,true) + card('Phishing DNA',dna) + card('Attack Surface Snapshot',snapshot) + card('Threat intelligence',intelligence) + card('Website / domain / TLS',technical) +
        card('Threat Relationship Graph', '<p class="scan-note">Choose an entity to inspect its direct connections. A source reference does not by itself indicate compromise.</p><div id="threatGraph" class="threat-graph"></div><p id="graphSelection" class="screen-reader-only" aria-live="polite"></p>',true) + card('Evidence Timeline',timeline) + card('Coverage and unavailable evidence',`<p>${esc(data.score_note)}</p>${missing}`);
    element('scanEvidence').hidden = false;
    renderGraph(data.threat_graph);
}

function renderGraph(graph) {
    const root = element('threatGraph');
    const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
    const byId = new Map(nodes.map(node => [node.id, node]));
    const edges = (Array.isArray(graph?.edges) ? graph.edges : []).filter(edge => byId.has(edge.from) && byId.has(edge.to));
    if (!nodes.length) {
        root.innerHTML = '<p class="graph-empty">No relationship entities were collected in this scan.</p>';
        return;
    }
    const kinds = {url:'Website URL', resource:'Resource', domain:'Domain', form:'Form', destination:'Form destination', iframe:'Iframe', indicator:'Threat indicator'};
    function description(node) {
        const kind = node.kind === 'url' && node.label.startsWith('Submitted:') ? 'Submitted URL' : node.kind === 'url' && node.label.startsWith('Fetched:') ? 'Final URL' : kinds[node.kind] || node.kind;
        if (['url', 'resource', 'iframe', 'destination'].includes(node.kind)) {
            try {
                const url = new URL(node.value);
                const path = url.pathname === '/' ? '/' : url.pathname;
                return {kind, name:url.hostname, detail:node.kind === 'resource' ? `${node.label.split(': ')[0]} · ${path}` : path};
            } catch { /* Non-URL values remain readable without inventing a destination. */ }
        }
        return {kind, name:node.kind === 'indicator' || node.kind === 'form' ? node.label : node.value, detail:kind};
    }
    const grouped = new Map();
    nodes.forEach(node => {
        const kind = kinds[node.kind] || node.kind;
        if (!grouped.has(kind)) grouped.set(kind, []);
        grouped.get(kind).push(node);
    });
    root.innerHTML = `<div class="graph-toolbar"><label for="graphEntity">Inspect entity</label><select id="graphEntity">${[...grouped].map(([kind, items]) => `<optgroup label="${esc(kind)}">${items.map(node => {
        const d = description(node);
        return `<option value="${esc(node.id)}">${esc(d.name)} · ${esc(d.detail)}</option>`;
    }).join('')}</optgroup>`).join('')}</select><span class="graph-count">${nodes.length} entities · ${edges.length} relationships</span></div><div class="graph-map" id="graphMap"></div><p class="scan-note graph-note">${esc(graph.note || 'Only recorded scan relationships are shown.')}</p>`;
    const picker = element('graphEntity');
    const map = element('graphMap');
    function relatedList(links, incoming) {
        if (!links.length) return `<p class="graph-empty">No ${incoming ? 'incoming' : 'outgoing'} relationships recorded.</p>`;
        return `<ul class="graph-links">${links.map(edge => {
            const node = byId.get(incoming ? edge.from : edge.to);
            const d = description(node);
            return `<li><button type="button" class="graph-entity" data-node-id="${esc(node.id)}" title="${esc(node.value)}"><span class="graph-edge-label">${esc(edge.label)}</span><strong>${esc(d.name)}</strong>${d.detail !== d.kind ? `<span class="graph-entity-detail">${esc(d.detail)}</span>` : ''}<span class="graph-kind">${esc(d.kind)}</span></button></li>`;
        }).join('')}</ul>`;
    }
    function choose(id, moveFocus = false) {
        const node = byId.get(id);
        if (!node) return;
        picker.value = id;
        const incoming = edges.filter(edge => edge.to === id);
        const outgoing = edges.filter(edge => edge.from === id);
        const d = description(node);
        map.innerHTML = `<section class="graph-neighbors"><h4>Incoming <span>${incoming.length}</span></h4>${relatedList(incoming, true)}</section><span class="graph-direction" aria-hidden="true">${incoming.length ? '→' : ''}</span><section class="graph-focus"><p class="graph-kind">${esc(d.kind)}</p><h4 tabindex="-1" data-focused-node>${esc(d.name)}</h4><p class="graph-focus-value">${esc(node.value)}</p><p class="graph-focus-count">${incoming.length} incoming · ${outgoing.length} outgoing</p></section><span class="graph-direction" aria-hidden="true">${outgoing.length ? '→' : ''}</span><section class="graph-neighbors"><h4>Outgoing <span>${outgoing.length}</span></h4>${relatedList(outgoing, false)}</section>`;
        element('graphSelection').textContent = `Selected ${d.kind}: ${node.value}. ${incoming.length} incoming and ${outgoing.length} outgoing relationships.`;
        if (moveFocus) map.querySelector('[data-focused-node]').focus();
    }
    picker.addEventListener('change', () => choose(picker.value));
    map.addEventListener('click', event => {
        const button = event.target.closest('button[data-node-id]');
        if (button) choose(button.dataset.nodeId, true);
    });
    choose((nodes.find(node => node.kind === 'url') || nodes[0]).id);
}

async function scanWebsite(force = false) {
    if (isScanning) return;
    const url = element('urlInput').value.trim();
    if (!url) { formatResult({error:'Enter a website URL.'}); element('resultsSection').style.display='block'; element('urlInput').focus(); return; }
    isScanning = true; element('scanBtn').disabled = true; element('bulkScanBtn').disabled = true; currentResult = null;
    viewState.pending = true; saveState();
    showLoading(); element('bulkResultsSection').style.display='none';
    try { formatResult(await requestJSON('/scan',{url,force:force === true,progress_id:scanSocket?.connected ? scanSocket.id : null})); }
    catch (error) { formatResult({error:error.message}); }
    finally { isScanning=false; delete viewState.pending; saveState(); element('scanBtn').disabled=false; element('bulkScanBtn').disabled=false; }
}

async function fetchData() {
    if (isScanning) return;
    element('historySection').style.display='block'; element('resultsSection').style.display='none';
    element('historyContainer').textContent='Loading actual scan history…';
    try {
        const data = await requestJSON('/get_data');
        element('historyContainer').innerHTML = data.data.length ? data.data.slice().reverse().map(item => `<div class="history-item"><div class="url">${esc(item.url)}</div><div>${esc(item.assessment)} · ${item.risk_score}/100 · ${esc(item.state)}</div><small>${esc(dateText(item.timestamp))}</small><button class="secondary-button" data-scan-id="${esc(item.scan_id)}">View stored evidence</button></div>`).join('') : '<p>No real scans stored yet.</p>';
        element('historyContainer').querySelectorAll('[data-scan-id]').forEach(button => button.addEventListener('click',() => loadScan(button.dataset.scanId)));
    } catch(error) { element('historyContainer').textContent=error.message; }
}

async function loadScan(id) {
    showLoading('Loading stored evidence. No new crawl is running.');
    try { const data=await requestJSON(`/api/scans/${encodeURIComponent(id)}`); formatResult({...data,cached:true}); element('resultsSection').scrollIntoView({block:'start',behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'}); }
    catch(error) { formatResult({error:error.message}); }
}

async function downloadReport() {
    if (!currentResult?.scan_id) return;
    reportButtons(false);
    try {
        const reportUrl=`/download_report?scan_id=${encodeURIComponent(currentResult.scan_id)}`;
        // A normal HTTP attachment also works in browsers without blob-download support.
        const response=await fetch(reportUrl,{method:'HEAD'});
        if(!response.ok) throw new Error('Stored report is unavailable. Complete a new scan and retry.');
        const link=document.createElement('a'); link.href=reportUrl;
        link.download=`phish-x-ai-${currentResult.scan_id.slice(0,8)}.pdf`;
        document.body.append(link); link.click(); link.remove();
    } catch(error) { element('scanMeta').textContent=error.message; }
    finally { reportButtons(Boolean(currentResult?.scan_id)); }
}

function displayBulkResults(data) {
    document.querySelector('.container').classList.add('has-analysis');
    element('totalScanned').textContent=data.total_scanned; element('safeCount').textContent=data.safe_count;
    element('suspiciousCount').textContent=data.suspicious_count; element('errorCount').textContent=data.failed_scans;
    element('bulkResultsList').innerHTML=data.results.map(result => `<div class="result-item ${result.risk_score >= 30 ? 'suspicious' : result.assessment === 'UNKNOWN' ? 'unknown' : 'safe'}"><div class="result-url">${esc(result.url)}<small>${esc(result.state)} · ${esc(result.assessment)} · ${result.risk_score}/100</small></div><button class="secondary-button" data-scan-id="${esc(result.scan_id)}">View evidence</button></div>`).join('');
    element('bulkResultsList').querySelectorAll('[data-scan-id]').forEach(button => button.addEventListener('click',() => loadScan(button.dataset.scanId)));
    element('bulkErrorsList').innerHTML=data.errors.length ? data.errors.map(error => `<div class="result-item error-item"><div>${esc(error.url)}</div><p>${esc(error.error)}</p></div>`).join('') : '<p>No rejected inputs.</p>';
    viewState = {view:'bulk', bulkResult:{...data, results:data.results.map(result => ({scan_id:result.scan_id, url:result.url, risk_score:result.risk_score, assessment:result.assessment, state:result.state}))}};
    saveState();
}

function switchTab(tab, button) {
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.toggle('active',btn===button));
    element('bulkResultsList').style.display=tab==='results'?'grid':'none'; element('bulkErrorsList').style.display=tab==='errors'?'grid':'none';
}

async function bulkScan() {
    if (isScanning) return;
    const urls=Array.from(document.querySelectorAll('.bulk-url-line')).map(input => input.value.trim()).filter(Boolean);
    if (!urls.length) { formatResult({error:'Enter at least one URL for bulk scanning.'}); element('resultsSection').style.display='block'; return; }
    isScanning=true; element('scanBtn').disabled=true; element('bulkScanBtn').disabled=true;
    viewState.pending = true; saveState();
    showLoading('Scanning submitted URLs with the same real evidence pipeline.');
    try { const data=await requestJSON('/bulk_scan',{urls}); hideLoading(); element('resultsSection').style.display='none'; element('bulkResultsSection').style.display='block'; displayBulkResults(data); }
    catch(error) { formatResult({error:error.message}); }
    finally { isScanning=false; delete viewState.pending; saveState(); element('scanBtn').disabled=false; element('bulkScanBtn').disabled=false; }
}

document.addEventListener('input', event => {
    if (event.target.matches('#urlInput, .bulk-url-line')) saveState();
});
window.addEventListener('pagehide', saveState);
window.addEventListener('pageshow', event => {
    if (event.persisted && isScanning) {
        isScanning = false;
        element('scanBtn').disabled = false;
        element('bulkScanBtn').disabled = false;
        if (currentResult) formatResult(currentResult);
        else formatResult({error:'The scan was interrupted by navigation. Submit the URL again to retry.'});
    }
});
document.addEventListener('DOMContentLoaded', () => {
    const saved = readState();
    if (typeof saved.url === 'string') element('urlInput').value = saved.url;
    if (Array.isArray(saved.bulk)) {
        while (document.querySelectorAll('.bulk-url-line').length < Math.min(saved.bulk.length, 10)) {
            if (typeof addRowAfter !== 'function') break;
            addRowAfter(document.querySelectorAll('.bulk-url-line').length - 1, false);
        }
        while (document.querySelectorAll('.bulk-url-line').length > Math.max(1, saved.bulk.length)) removeRowAt(document.querySelectorAll('.bulk-url-line').length - 1);
        document.querySelectorAll('.bulk-url-line').forEach((input,index) => input.value = typeof saved.bulk[index] === 'string' ? saved.bulk[index] : '');
    }
    if (saved.view === 'single' && saved.result?.schema_version === 5 && saved.result?.scan_id) {
        element('resultsSection').style.display = 'block';
        formatResult(saved.result);
    } else if (saved.view === 'bulk' && Array.isArray(saved.bulkResult?.results)) {
        element('bulkResultsSection').style.display = 'block';
        displayBulkResults(saved.bulkResult);
    }
    if (saved.pending) {
        element('resultsSection').style.display = 'block';
        if (!currentResult) formatResult({error:'The scan was interrupted by navigation. Submit the URL again to retry.'});
        else element('scanMeta').textContent += ' · A later scan was interrupted by navigation; this is the previous completed result.';
    }
    if (saved.view && saved.view !== 'none' && Number.isFinite(saved.scrollY)) {
        requestAnimationFrame(() => window.scrollTo({top:saved.scrollY, behavior:'instant'}));
    }
});
