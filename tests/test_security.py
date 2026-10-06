"""Offline controlled fixtures; none of these are production scan records."""
import copy
import io
import json
import socket
import ssl
import time
import zlib
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from pypdf import PdfReader, PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject

import secure_fetch as sf
import features_extract as fe
import threat_intelligence as ti
from ai_analysis import validate_ai_result, analyze_with_ai
from file_analysis import inspect_pdf
from risk_engine import assess_risk
from storage import ScanStore


@pytest.mark.parametrize('value',['','file:///etc/passwd','ftp://example.com','javascript:alert(1)','https://user:secret@example.com','https://exa mple.com','https://example.com:8443','https://bad_host.com','http://[::1','https://example.com\\@localhost','https://example.com\n/x'])
def test_invalid_url(value):
    with pytest.raises(sf.ScanError): sf.normalize_url(value)


@pytest.mark.parametrize('value',['http://127.0.0.1','http://127.0.0.2','http://10.0.0.1','http://172.16.0.1','http://192.168.1.1','http://169.254.169.254','http://100.100.100.200','http://168.63.129.16','http://[::1]','http://[fc00::1]','http://[fe80::1]','http://[::ffff:127.0.0.1]','http://[64:ff9b::7f00:1]','http://localhost','http://metadata.google.internal','http://host.local'])
def test_private_targets(value):
    with pytest.raises(sf.ScanError): sf.resolve_target(value)


def test_mixed_dns_is_rejected(monkeypatch):
    monkeypatch.setattr(sf.dns.resolver.Resolver,'resolve',lambda self,host,kind,**kw: ['8.8.8.8','127.0.0.1'] if kind=='A' else [])
    with pytest.raises(sf.ScanError,match='non-public'): sf.resolve_target('https://mixed.example.com')


def test_every_redirect_is_validated(monkeypatch):
    calls=[]
    def once(target,deadline,max_bytes):
        calls.append(target.url)
        return {'status_code':302,'headers':{'location':'http://169.254.169.254/latest/meta-data/'},'connected_ip':'8.8.8.8','tls':{}}
    monkeypatch.setattr(sf,'request_once',once)
    initial=sf.Target('https://example.com/','example.com',443,'https',['8.8.8.8'])
    with pytest.raises(sf.ScanError) as error: sf.fetch_website(initial.url, initial=initial)
    assert error.value.code=='blocked_destination'
    assert len(error.value.redirect_chain)==1
    assert len(calls)==1


def test_redirect_loop_and_limit(monkeypatch):
    monkeypatch.setattr(sf,'resolve_target',lambda url,deadline:sf.Target(url,urlsplit(url).hostname,443,'https',['8.8.8.8']))
    monkeypatch.setattr(sf,'request_once',lambda target,*args:{'status_code':301,'headers':{'location':target.url},'connected_ip':'8.8.8.8','tls':{}})
    with pytest.raises(sf.ScanError,match='loop'): sf.fetch_website('https://example.com')


def test_dns_rebinding_cannot_change_connected_ip(monkeypatch):
    seen=[]
    class FakeSocket:
        def getpeername(self): return ('8.8.8.8',80)
        def settimeout(self,value): pass
    class Response:
        status=200
        def getheaders(self): return [('Content-Type','text/html')]
        def read1(self,size): return b''
    class Connection:
        def __init__(self,host,port,timeout): self.host=host; self.sock=FakeSocket()
        def connect(self): self._create_connection(('127.0.0.1',80),2)
        def request(self,*args,**kwargs): seen.append(self.host)
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr(sf.http.client,'HTTPConnection',Connection)
    monkeypatch.setattr(sf,'_pinned_socket',lambda ip,port,timeout: seen.append(ip) or FakeSocket())
    target=sf.Target('http://example.com/','example.com',80,'http',['8.8.8.8'])
    sf.request_once(target,time.monotonic()+5,100)
    assert seen==['8.8.8.8','example.com']


def html_features(html, url='https://example.com/'):
    response={'final_url':url,'body':html.encode(),'headers':{'content-type':'text/html'},'truncated':False}
    content=fe.parse_content(response)
    return {'_original_url':url,'url':fe.extract_url_features(url),'url_structure':fe.analyze_url_structure(url),'keywords':fe.extract_keyword_features(url),
            'domain':fe.extract_domain_features(url),'shortener':fe.is_shortened_url(url),'content':content,'http':{'status':'completed','status_code':200,'final_url':url,'bytes_received':len(html)},
            'dns':{'status':'completed','addresses':['8.8.8.8']},'certificate':{'status':'completed','verified':True},'redirection':{'status':'completed','chain':[]},
            'domain_age':{'status':'unavailable','domain_age_days':None},'virus_total':{'status':'not_configured'},'google_safe_browsing':{'status':'not_configured'},
            'security_headers':{},'brand_impersonation':fe.detect_brand_impersonation(url,content['title'],bool(content['password_fields']))}


def test_real_form_evidence_and_script_combinations():
    f=html_features('<title>PayPal sign in</title><form action="http://other-site.net/receive" method="get"><input type="password"><input autocomplete="cc-number"></form><script>eval(atob("c29tZSB0ZXh0"));</script>')
    risk=assess_risk(f)
    assert risk['score']>=60
    assert f['content']['password_fields']==1 and f['content']['payment_fields']==1
    assert any(e['id'].startswith('form.external') for e in risk['evidence'])
    assert any(e['id'].startswith('script.obfuscation') for e in risk['evidence'])
    assert all(e['source'] and e['detail'] is not None for e in risk['evidence'])
    assert risk['score']==min(100,sum(e['points'] for e in risk['evidence']))


def test_keywords_eval_missing_mail_are_not_proof():
    f=html_features('<title>Account login security research</title><form method="post"><input type="password"></form><script>eval("x");</script>', 'https://example.com/login/account/verify')
    f['email']={'spf_present':False,'dmarc_present':False}
    risk=assess_risk(f)
    assert risk['score']<10
    assert risk['assessment']=='SAFE'


def test_brand_reference_in_path_is_not_impersonation():
    assert not fe.detect_brand_impersonation('https://example.com/tutorials/google/login')['is_impersonating']
    assert fe.detect_brand_impersonation('https://paypal-login.example.net/')['is_impersonating']
    assert fe.same_site('login.example.co.uk','www.example.co.uk')
    assert not fe.same_site('example.co.uk','other.co.uk')


def test_missing_content_never_means_safe():
    f=html_features('')
    f['content']={'status':'unavailable','reason':'Timeout'}
    f['http']={'status':'timeout','reason':'Timeout'}
    risk=assess_risk(f)
    assert risk['assessment']=='UNKNOWN' and risk['state']=='timeout'
    assert risk['score']==0
    assert not next(d for d in risk['dna'] if d['key']=='credentials')['available']


def test_http_200_block_page_is_detected():
    f=html_features('<title>Your request has been blocked. This could be due to several reasons.</title>')
    assert f['content']['status']=='blocked_by_target'
    assert assess_risk(f)['assessment']=='UNKNOWN'


def test_script_private_destination_is_not_fetched(monkeypatch):
    called=[]
    monkeypatch.setattr(sf,'request_once',lambda *args:called.append(args))
    f=html_features('<script src="http://127.0.0.1/private.js"></script>')
    assert not called
    assert f['content']['script_fetches'][0]['status']=='blocked_destination'


def test_form_base_and_formaction_are_resolved():
    f=html_features('<base href="https://other-site.net/"><form method="post" action="receive"><input type="password"><button formaction="http://169.254.169.254/send">Send</button></form>')
    assert f['content']['forms'][0]['actions'][0]['external']
    assert f['content']['forms'][0]['actions'][1]['internal_literal']


def test_vt_submission_polls_analysis_status(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','test-not-real')
    calls=[]
    replies=iter([(404,{},{}),(200,{}, {'data':{'id':'controlled-test'}}),(200,{}, {'data':{'attributes':{'status':'queued'}}}),
                  (200,{}, {'data':{'attributes':{'status':'completed','stats':{'malicious':2,'suspicious':1,'harmless':4,'undetected':3},'results':{'vendor':{'category':'malicious','result':'phishing'}}}}})])
    def api(method,path,*args,**kwargs): calls.append((method,path)); return next(replies)
    monkeypatch.setattr(ti,'_vt_request',api); monkeypatch.setattr(ti.time,'sleep',lambda seconds:None)
    result=ti.check_url_virustotal('https://example.com')
    assert result['status']=='completed' and result['total']==10
    assert calls[-1][1]=='analyses/controlled-test'
    assert result['vendors'][0]['vendor']=='vendor'


@pytest.mark.parametrize('response,expected',[(429,'rate_limited'),(401,'unauthorized'),(500,'error')])
def test_vt_http_errors_are_not_counts(monkeypatch,response,expected):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','test-not-real')
    monkeypatch.setattr(ti,'_vt_request',lambda *a,**kw:(response,{},{}))
    result=ti.check_url_virustotal('https://example.com')
    assert result['status']==expected and 'malicious' not in result


def test_vt_malformed_completed_report(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','test-not-real')
    monkeypatch.setattr(ti,'_vt_request',lambda *a,**kw:(200,{}, {'data':{'attributes':{'last_analysis_stats':{'malicious':'fake'}}}}))
    assert ti.check_url_virustotal('https://example.com')['status']=='error'


def test_ai_requires_real_service_and_cited_evidence(monkeypatch):
    monkeypatch.delenv('OPENAI_API_KEY',raising=False); monkeypatch.delenv('OLLAMA_MODEL',raising=False); monkeypatch.setenv('AI_PROVIDER','auto')
    f=html_features('<title>Example</title>')
    risk=assess_risk(f)
    assert analyze_with_ai(f,risk)['status']=='not_configured'
    ai={'assessment':'SAFE','confidence':0.8,'key_reasons':[{'interpretation':'No strong threat evidence was observed.','evidence_ids':['html.observed']}],'recommended_action':'verify_context','limitations':['Static inspection only.']}
    assert validate_ai_result(ai,risk)['status']=='completed'
    ai['key_reasons'][0]['evidence_ids']=['invented.fact']
    with pytest.raises(ValueError): validate_ai_result(ai,risk)


def test_ai_network_failure_is_explicit(monkeypatch):
    import ai_analysis as ai
    import requests
    monkeypatch.setenv('AI_PROVIDER','openai'); monkeypatch.setenv('OPENAI_API_KEY','test-not-real')
    monkeypatch.setattr(ai,'api_json',lambda *a,**kw: (_ for _ in ()).throw(requests.Timeout()))
    f=html_features('')
    assert ai.analyze_with_ai(f,assess_risk(f))['status']=='unavailable'


def test_pdf_object_javascript_and_uri(tmp_path):
    writer=PdfWriter(); page=writer.add_blank_page(width=300,height=300)
    writer.add_open_action(DictionaryObject({NameObject('/S'):NameObject('/JavaScript'),NameObject('/JS'):TextStringObject('/* controlled static inspection fixture; no executable payload */')}))
    page[NameObject('/Annots')]=__import__('pypdf').generic.ArrayObject([DictionaryObject({NameObject('/Type'):NameObject('/Annot'),NameObject('/Subtype'):NameObject('/Link'),NameObject('/A'):DictionaryObject({NameObject('/S'):NameObject('/URI'),NameObject('/URI'):TextStringObject('https://example.com/')})})])
    path=tmp_path/'controlled.pdf'; writer.write(path)
    result=inspect_pdf(str(path))
    assert result['javascript'] and 'example.com' in result['actions'][0]


def test_route_rejects_client_verdict_and_report_reuses_scan(monkeypatch,tmp_path):
    monkeypatch.setenv('LOCAL_DB_PATH',str(tmp_path/'scans.sqlite3')); monkeypatch.setenv('SCAN_REQUESTS_PER_MINUTE','1000')
    import app as application
    monkeypatch.setattr(application,'store',ScanStore())
    calls=[]
    monkeypatch.setattr(application,'analyze_url',lambda url,*a:calls.append(url) or html_features('<title>Controlled fixture</title>'))
    monkeypatch.setattr(application,'analyze_with_ai',lambda *a:{'status':'not_configured','reason':'Offline test fixture'})
    client=application.app.test_client()
    response=client.post('/extract_features',json={'url':'https://example.com','is_phishing':'1','risk_score':99,'title':'Client spoof'})
    assert response.status_code==200
    result=response.json
    assert result['risk_score']==0 and not result['is_phishing'] and result['title']=='Controlled fixture'
    cached=client.post('/scan',json={'url':'example.com'}).json
    assert cached['cached'] and cached['features']==result['features'] and len(calls)==1
    report=client.post('/download_report',json={'scan_id':result['scan_id']})
    assert report.status_code==200 and report.data.startswith(b'%PDF-') and len(calls)==1
    report_url='/download_report?scan_id='+result['scan_id']
    assert client.head(report_url).status_code==200
    assert client.get(report_url).data.startswith(b'%PDF-') and len(calls)==1
    text=''.join(p.extract_text() for p in PdfReader(io.BytesIO(report.data)).pages)
    assert 'not_configured' in text and 'Controlled fixture' in text
    assert client.post('/download_report',json={'scan_id':'not-found'}).status_code==409
    assert client.get('/dashboard').status_code==200
    assert len(client.get('/get_data').json['data'])==1


def test_file_endpoint_type_checks(monkeypatch,tmp_path):
    import app as application
    monkeypatch.setenv('SCAN_REQUESTS_PER_MINUTE','1000')
    client=application.app.test_client()
    assert client.post('/analyze_pdf',data={'pdf':(io.BytesIO(b'PK fake'),'wrong.pdf')}).status_code==400
    assert client.post('/analyze_apk',data={'apk':(io.BytesIO(b'%PDF fake'),'wrong.apk')}).status_code==400
    assert client.post('/analyze_apk',data={'apk':(io.BytesIO(b'PK'),'wrong.pdf')}).status_code==400
    assert client.post('/scan',json={'url':[]}).status_code==400
    assert client.post('/scan',json={'url':'https://example.com','progress_id':{}}).status_code==400
    assert client.post('/scan',json={'url':'https://example.com'},headers={'Origin':'https://other.example'}).status_code==403


def test_response_and_decompression_limits(monkeypatch):
    compressed=zlib.compressobj(wbits=16+zlib.MAX_WBITS)
    payload=compressed.compress(b'A'*10000)+compressed.flush()
    class FakeSocket:
        def settimeout(self,value): pass
    class Response:
        status=200
        def __init__(self): self.chunks=iter([payload,b''])
        def getheaders(self): return [('Content-Type','text/html'),('Content-Encoding','gzip')]
        def read1(self,size): return next(self.chunks)
    class Connection:
        def __init__(self,*args,**kwargs): self.sock=FakeSocket()
        def connect(self): self._create_connection(("example.com",80),2)
        def request(self,*args,**kwargs): pass
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr(sf.http.client,'HTTPConnection',Connection)
    monkeypatch.setattr(sf,'_pinned_socket',lambda *args: FakeSocket())
    result=sf.request_once(sf.Target('http://example.com/','example.com',80,'http',['8.8.8.8']),time.monotonic()+5,100)
    assert result['truncated'] and len(result['body'])==100


def test_tls_and_timeout_never_fetch_unverified_content(monkeypatch):
    class Connection:
        def __init__(self,*args,**kwargs): pass
        def connect(self): raise ssl.SSLCertVerificationError()
        def close(self): pass
    monkeypatch.setattr(sf.http.client,'HTTPSConnection',Connection)
    with pytest.raises(sf.ScanError) as error:
        sf.request_once(sf.Target('https://example.com/','example.com',443,'https',['8.8.8.8']),time.monotonic()+5,100)
    assert error.value.code=='tls_error'
    monkeypatch.setattr(Connection,'connect',lambda self:(_ for _ in ()).throw(socket.timeout()))
    with pytest.raises(sf.ScanError) as error:
        sf.request_once(sf.Target('https://example.com/','example.com',443,'https',['8.8.8.8']),time.monotonic()+5,100)
    assert error.value.code=='timeout'


def test_vt_pending_analysis_never_claims_counts(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','test-not-real')
    replies=iter([(404,{},{}),(200,{}, {'data':{'id':'controlled-test'}}),(200,{}, {'data':{'attributes':{'status':'queued'}}}),(200,{}, {'data':{'attributes':{'status':'queued'}}})])
    monkeypatch.setattr(ti,'_vt_request',lambda *a,**kw:next(replies)); monkeypatch.setattr(ti.time,'sleep',lambda seconds:None)
    result=ti.check_url_virustotal('https://example.com')
    assert result['status']=='queued' and 'malicious' not in result


def test_zero_dna_dimensions_have_observation_sources():
    f=html_features('<title>Example</title>')
    risk=assess_risk(f)
    for key in ('redirects','identity','relationships','scripts'):
        dimension=next(d for d in risk['dna'] if d['key']==key)
        assert dimension['available'] and dimension['points']==0 and dimension['evidence_ids']


def test_ai_rejects_invented_numbers_and_warning_downgrade():
    f=html_features('<title>Example</title>')
    risk=assess_risk(f)
    ai={'assessment':'SAFE','confidence':0.8,'key_reasons':[{'interpretation':'There are 999 password fields.','evidence_ids':['html.observed']}],'recommended_action':'verify_context','limitations':[]}
    with pytest.raises(ValueError): validate_ai_result(ai,risk)
    ai['key_reasons'][0]['interpretation']='No strong threat evidence was observed.'
    risk.update(score=85, severity='CRITICAL', assessment='CRITICAL')
    with pytest.raises(ValueError): validate_ai_result(ai,risk)


def test_mongo_failure_preserves_actual_local_results(monkeypatch,tmp_path):
    from pymongo.errors import ConnectionFailure
    monkeypatch.setenv('LOCAL_DB_PATH',str(tmp_path/'fallback.sqlite3'))
    storage=ScanStore()
    class UnavailableCollection:
        def replace_one(self,*args,**kwargs): raise ConnectionFailure('Controlled unavailable database')
    storage.collection=UnavailableCollection()
    record={'scan_id':'controlled-storage-fixture','schema_version':__import__('storage').SCHEMA_VERSION,'url':'https://example.com/','timestamp':'2026-10-05T00:00:00+00:00','features':{'http':{'status':'completed'}},'evidence':[]}
    storage.save(record)
    assert storage.mode=='local_sqlite' and storage.get(record['scan_id'])==record
    assert storage.cached(record['url'])['features']==record['features']
    assert storage.recent()==[record]


def test_serverless_configuration_uses_http_limits(monkeypatch,tmp_path):
    import subprocess,sys,os
    script="""
import app
assert app.SERVERLESS and app.socketio is None
assert app.store.mode == 'ephemeral_sqlite'
c=app.app.test_client()
r=c.get('/api/capabilities').json
assert r['bulk_limit']==2 and r['upload_limit_mb']==4 and not r['socketio'] and not r['ai_configured']
assert c.post('/scan',json={'url':'https://example.com'}).status_code==503
# Exercise route limits separately from the missing-database production gate.
app.production_issues=lambda:[]
app.store.rate_allowed=lambda *a:True
assert c.post('/crawl',json={'url':'https://example.com','follow_links':True}).json['code']=='serverless_limit'
assert c.post('/bulk_scan',json={'urls':['a','b','c']}).status_code==400
assert 'socket.io.min.js' not in c.get('/').text
assert c.post('/scan',data=b'x'*(4*1024*1024+1),content_type='application/json').status_code==413
print('Serverless HTTP mode and limits verified')
"""
    env={**os.environ,'VERCEL':'1','LOCAL_DB_PATH':str(tmp_path/'serverless.sqlite3'),'MONGODB_URI':'','MONGO_URI':'','AI_PROVIDER':'none'}
    result=subprocess.run([sys.executable,'-c',script],cwd=Path(__file__).resolve().parents[1],env=env,capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr


def test_report_handles_long_untrusted_table_values(monkeypatch,tmp_path):
    import app as application
    from reports import build_report
    monkeypatch.setenv('LOCAL_DB_PATH',str(tmp_path/'report-fixture.sqlite3'))
    monkeypatch.setattr(application,'store',ScanStore())
    monkeypatch.setattr(application,'analyze_url',lambda *a:html_features('<title>Long fixture</title>'))
    monkeypatch.setattr(application,'analyze_with_ai',lambda *a:{'status':'not_configured','reason':'Offline fixture'})
    result=application.process_url('https://long-title.example.com',force=True)
    result['features']['content']['title']='A'*20000
    result['attack_surface']['external_domains']=['resource-'+str(i)+'.example.net' for i in range(1000)]
    report=build_report(result)
    assert report.read(5)==b'%PDF-'


@pytest.mark.parametrize('code,status',[('insufficient_quota','quota_exceeded'),('credit_balance_exhausted','quota_exceeded'),('rate_limit_exceeded','rate_limited')])
def test_openai_quota_and_rate_limits_are_explicit(monkeypatch,code,status):
    import ai_analysis as ai
    monkeypatch.setenv('AI_PROVIDER','openai'); monkeypatch.setenv('OPENAI_API_KEY','test-not-real')
    monkeypatch.setattr(ai,'api_json',lambda *a,**kw:(429,{}, {'error':{'code':code}}))
    f=html_features('')
    result=ai.analyze_with_ai(f,assess_risk(f))
    assert result['status']==status and result['error_code']==code
    assert 'confidence' not in result and 'key_reasons' not in result


def test_crawler_follows_only_bounded_discovered_links(monkeypatch,tmp_path):
    import app as application
    monkeypatch.setenv('LOCAL_DB_PATH',str(tmp_path/'crawl-fixture.sqlite3'))
    monkeypatch.setenv('SCAN_REQUESTS_PER_MINUTE','1000')
    monkeypatch.setattr(application,'store',ScanStore())
    calls=[]
    def analyze(url,*args):
        calls.append(url)
        html='<a href="/logout">Logout</a><a href="/?token=x">Query</a><a href="https://other-site.net">External</a><a href="/about">About</a><a href="/help">Help</a><a href="/extra">Extra</a>'
        return html_features(html,url)
    monkeypatch.setattr(application,'analyze_url',analyze)
    monkeypatch.setattr(application,'analyze_with_ai',lambda *a:{'status':'not_configured','reason':'Offline fixture'})
    response=application.app.test_client().post('/crawl',json={'url':'https://example.com','follow_links':True})
    assert response.status_code==200 and response.json['followed_pages']==2
    assert calls==['https://example.com/','https://example.com/about','https://example.com/help']



def test_private_suffix_tenants_are_separate_sites():
    assert not fe.same_site('tenant-a.github.io','tenant-b.github.io')
    assert not fe.same_site('tenant-a.vercel.app','tenant-b.vercel.app')
    assert fe.same_site('www.tenant-a.github.io','tenant-a.github.io')
    f=html_features('<form method="post" action="https://tenant-b.github.io/receive"><input type="password"></form>','https://tenant-a.github.io/')
    assert f['content']['forms'][0]['actions'][0]['external']
    assert any(e['id'].startswith('form.external') for e in assess_risk(f)['evidence'])


def test_ai_context_prioritizes_significant_evidence():
    from ai_analysis import evidence_payload
    f=html_features('<title>Example</title>')
    risk=assess_risk(f)
    risk['evidence'] += [{'id':'observed.'+str(i),'detail':'Observed structure','points':0} for i in range(100)]
    risk['evidence'].append({'id':'intel.important','detail':{'malicious':10},'points':85})
    payload=evidence_payload(f,risk)
    assert len(payload['evidence'])==70 and payload['evidence'][0]['id']=='intel.important'


def test_vetted_connection_tries_next_public_address(monkeypatch):
    seen = []
    class Sock:
        def settimeout(self, value): assert 0 < value <= 4
    def connect(ip, port, timeout):
        seen.append(ip)
        if ip == '8.8.8.8': raise OSError('first address refused')
        return Sock()
    monkeypatch.setattr(sf, '_pinned_socket', connect)
    target = sf.Target('https://example.com/', 'example.com', 443, 'https', ['8.8.8.8', '1.1.1.1'])
    _, actual = sf._connect_vetted(target, time.monotonic() + 5)
    assert actual == '1.1.1.1' and seen == ['8.8.8.8', '1.1.1.1']


def test_connection_security_mismatch_never_retries(monkeypatch):
    seen = []
    def mismatch(ip, port, timeout):
        seen.append(ip)
        raise sf.ScanError('Connection address mismatch.', 'blocked_destination')
    monkeypatch.setattr(sf, '_pinned_socket', mismatch)
    target = sf.Target('https://example.com/', 'example.com', 443, 'https', ['8.8.8.8', '1.1.1.1'])
    with pytest.raises(sf.ScanError): sf._connect_vetted(target, time.monotonic() + 5)
    assert seen == ['8.8.8.8']
