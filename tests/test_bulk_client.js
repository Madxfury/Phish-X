const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/js/bulk-client.js'),'utf8'), context);
const scan = context.scanBulkBatches;
const response = urls => ({results:urls.map(url => ({url, scan_id:url})), errors:[], cached_results:0,
    new_scans:urls.length, suspicious_count:0, safe_count:urls.length, partial_count:0});

test('five URLs use bounded ordered requests and real progress totals', async () => {
    const requests=[], progress=[];
    const result=await scan(['a','b','c','d','e'],2, async batch => {requests.push([...batch]); return response(batch);},
        (done,total,batch) => progress.push([done,total,batch]));
    assert.deepEqual(requests,[['a','b'],['c','d'],['e']]);
    assert.deepEqual(progress,[[2,5,1],[4,5,2],[5,5,3]]);
    assert.equal(result.successful_scans,5); assert.equal(result.new_scans,5);
    assert.deepEqual(Array.from(result.results,x => x.url),['a','b','c','d','e']);
});
test('each URL appears once and no batch runs concurrently with another', async () => {
    let active=0, count=0;
    const result=await scan(Array.from({length:10},(_,i)=>String(i)),2,async batch => {
        active++; assert.equal(active,1); await Promise.resolve(); count++; active--; return response(batch);
    });
    assert.equal(count,5); assert.equal(result.results.length,10);
});
test('per-URL rejection is retained while later batches can complete', async () => {
    const result=await scan(['good','bad','later'],2,async batch => batch.includes('bad') ? {
        ...response(['good']),errors:[{url:'bad',error:'Unsupported protocol',code:'invalid_input'}]
    }:response(batch));
    assert.equal(result.successful_scans,2); assert.equal(result.failed_scans,1);
    assert.equal(result.safe_count,2); assert.equal(result.errors[0].code,'invalid_input');
});
test('request failure preserves completed results and marks later URLs unscanned', async () => {
    let calls=0;
    const result=await scan(['a','b','c','d','e'],2,async batch => {
        if (++calls===2) throw new Error('Too many scan requests.'); return response(batch);
    });
    assert.equal(calls,2); assert.equal(result.results.length,2); assert.equal(result.failed_scans,3);
    assert.equal(result.errors[0].code,'request_failed'); assert.equal(result.errors[2].code,'not_scanned');
    assert.equal(result.new_scans,2); assert.equal(result.total_scanned,5);
});
test('malformed responses never acquire invented verdicts', async () => {
    const result=await scan(['a'],2,async()=>({results:[],errors:[]}));
    assert.equal(result.results.length,0); assert.equal(result.failed_scans,1);
    assert.match(result.errors[0].error,/incomplete/);
});
test('invalid batch sizes use safe two-URL requests and invalid lists are rejected', async () => {
    const batches=[];
    await scan(['a','b','c'],500,async urls => {batches.push(urls.length);return response(urls);});
    assert.deepEqual(batches,[2,1]);
    for (const urls of [[],null,[1],Array(11).fill('a')]) await assert.rejects(scan(urls,2,async()=>{}));
});

const head=fs.readFileSync(path.join(__dirname,'../templates/index.html'),'utf8').match(/<script>\s*([\s\S]*?)<\/script>/)[1];
function start(type, denied=false) {
    const data=new Map([['phishx.introSeen','1'],['phishx.scanState.v1','previous'],['other','keep']]);
    const classes=[], history={}, window={};
    vm.runInNewContext(head,{window,history,performance:{getEntriesByType:()=>[{type}]},
        sessionStorage:{getItem:k=>{if(denied)throw Error('Denied');return data.get(k);}, removeItem:k=>{if(denied)throw Error('Denied');data.delete(k);}},
        document:{documentElement:{classList:{add:c=>classes.push(c)}}}});
    return {data,classes,window,history};
}
test('Home reload replays intro and clears visible state without clearing unrelated storage',()=>{
    const boot=start('reload');
    assert.equal(boot.window.PHISHX_RELOAD,true); assert.equal(boot.classes.length,0);
    assert.equal(boot.data.has('phishx.introSeen'),false); assert.equal(boot.data.has('phishx.scanState.v1'),false);
    assert.equal(boot.data.get('other'),'keep'); assert.equal(boot.history.scrollRestoration,'manual');
});
test('return navigation and back preserve the session and skip intro',()=>{
    for(const type of ['navigate','back_forward']) {
        const boot=start(type);assert.equal(boot.window.PHISHX_RELOAD,false);
        assert.deepEqual(boot.classes,['skip-intro']);assert.equal(boot.data.get('phishx.scanState.v1'),'previous');
    }
});
test('disabled session storage never prevents Home from opening',()=>{
    assert.equal(start('reload',true).window.PHISHX_RELOAD,true);
    assert.equal(start('navigate',true).classes.length,0);
});
