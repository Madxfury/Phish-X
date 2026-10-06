'use strict';
const socket = window.PHISHX_SOCKETIO && window.io ? io({transports:['polling','websocket'],timeout:5000}) : null;
const results = new Map();
let crawling = false;
const esc = value => String(value ?? '').replace(/[&<>"']/g,c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const el = id => document.getElementById(id);


async function boundedFetch(url, options = {}, timeout = 12000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
        const response = await fetch(url, {...options, signal: controller.signal});
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
        return data;
    } catch (error) {
        if (error.name === 'AbortError') throw new Error('Request timed out. Retry when the server is reachable; no completed crawl was received.');
        throw error;
    } finally { clearTimeout(timer); }
}

function renderResults() {
    const scans=[...results.values()].sort((a,b) => b.timestamp.localeCompare(a.timestamp)).slice(0,50);
    const safe=scans.filter(r => ['SAFE','LOW'].includes(r.assessment)).length;
    const risky=scans.filter(r => r.risk_score >= 30).length;
    el('total-sites').textContent=scans.length; el('safe-sites').textContent=safe; el('phishing-sites').textContent=risky;
    el('unknown-sites').textContent=scans.length-safe-risky;
    el('results-container').innerHTML=scans.length ? scans.map(result => `<div class="crawl-result ${result.risk_score >= 30 ? 'phishing' : result.assessment === 'UNKNOWN' ? '' : 'safe'}"><div class="d-flex justify-content-between gap-2 flex-wrap"><div><div class="url">${esc(result.url)}</div><div class="title">${esc(result.title)}</div></div><span class="status ${result.risk_score >= 30 ? 'phishing' : ''}">${esc(result.assessment)} · ${result.risk_score}/100</span></div><div>${esc(result.state.replaceAll('_',' '))}</div><div class="timestamp">${esc(new Date(result.timestamp).toLocaleString())}</div><button class="btn btn-outline-light mt-2" data-scan-id="${esc(result.scan_id)}">View crawl evidence</button></div>`).join('') : '<p>No real scans stored yet. Submit a URL to start.</p>';
    el('results-container').querySelectorAll('[data-scan-id]').forEach(button => button.addEventListener('click',async () => {
        try {
            const result=await boundedFetch(`/api/scans/${encodeURIComponent(button.dataset.scanId)}`);
            showEvidence(result);
        } catch(error) { el('crawlState').textContent=error.message; }
    }));
}

function showEvidence(result) {
    el('crawlState').textContent=`${result.assessment} · ${result.risk_score}/100 · ${result.state} · AI ${result.ai.status} · VirusTotal ${result.features.virus_total.status}`;
    el('crawlProgress').innerHTML=result.timeline.map(step => `<li><strong>${esc(step.stage)}</strong>: ${esc(step.status)} — ${esc(step.detail)}</li>`).join('') + `<li><strong>Attack surface</strong>: ${esc(JSON.stringify(result.attack_surface))}</li>` +
        result.evidence.filter(f => f.points > 0).map(f => `<li><strong>${esc(f.label)}</strong> (+${f.points}): ${esc(JSON.stringify(f.detail))}<br>Source: ${esc(f.source)}</li>`).join('');
}

async function poll() {
    try {
        const data=await boundedFetch('/get_data');
        data.data.forEach(result => results.set(result.scan_id,result)); renderResults();
    } catch { if(!crawling) el('crawlState').textContent='History connection unavailable. Retry a scan when the server is reachable.'; }
}

if(socket) socket.on('scan_stage',step => {
    if(!crawling) return;
    const item=document.createElement('li'); item.textContent=`${step.stage}: ${step.status} — ${step.detail}`;
    el('crawlProgress').append(item); el('crawlState').textContent=step.stage;
});

el('crawlForm').addEventListener('submit',async event => {
    event.preventDefault(); if(crawling) return;
    crawling=true; el('crawlButton').disabled=true; el('crawlProgress').replaceChildren();
    el('crawlState').textContent='Crawling submitted website. Stages appear only after actual observations.';
    try {
        const data=await boundedFetch('/crawl',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:el('crawlUrl').value.trim(),follow_links:el('followLinks').checked,progress_id:socket?.connected ? socket.id : null})}, 160000);
        data.results.forEach(result => results.set(result.scan_id,result)); renderResults(); showEvidence(data.results[0]);
        el('crawlState').textContent += ` · ${data.followed_pages} linked pages inspected`;
        if(data.errors.length) el('crawlState').textContent += ' · Some linked pages were rejected.';
    } catch(error) { el('crawlState').textContent=error.message || 'Crawl request failed.'; }
    finally { crawling=false; el('crawlButton').disabled=false; }
});
poll();
setInterval(() => { if(!document.hidden && !crawling) poll(); },10000);
