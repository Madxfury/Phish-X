"""Release regressions: visitor privacy, provider responses and production gates."""
import json
import pytest

import ai_analysis as ai
from storage import ScanStore, config_fingerprint
from risk_engine import assess_risk
from test_security import html_features


@pytest.fixture
def isolated_app(monkeypatch, tmp_path):
    import app as application
    for name in ('DATABASE_URL','POSTGRES_URL','MONGODB_URI','MONGO_URI'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('LOCAL_DB_PATH', str(tmp_path/'private-scans.sqlite3'))
    monkeypatch.setenv('SCAN_REQUESTS_PER_MINUTE','1000')
    monkeypatch.setattr(application,'store',ScanStore())
    monkeypatch.setattr(application,'analyze_url', lambda url,*a:html_features('<title>Controlled privacy fixture</title>',url))
    monkeypatch.setattr(application,'analyze_with_ai',lambda *a:{'status':'not_configured','reason':'Offline fixture'})
    return application


def test_other_visitor_cannot_read_scan_history_report_or_dashboard(isolated_app):
    app=isolated_app.app
    first,second=app.test_client(),app.test_client()
    scan=first.post('/scan',json={'url':'https://example.com/private-token-fixture'}).json
    assert first.get('/api/scans/'+scan['scan_id']).status_code==200
    assert first.get('/get_data').json['data'][0]['scan_id']==scan['scan_id']
    assert second.get('/get_data').json['data']==[]
    assert second.get('/api/scans/'+scan['scan_id']).status_code==404
    assert second.get('/download_report?scan_id='+scan['scan_id']).status_code==409
    assert second.get('/download_report?url='+scan['url']).status_code==409
    assert scan['url'] not in second.get('/dashboard').text
    assert not second.post('/scan',json={'url':scan['url']}).json['cached']
    assert first.post('/scan',json={'url':scan['url']}).json['cached']


def test_bulk_worker_retains_visitor_scope(isolated_app):
    first,second=isolated_app.app.test_client(),isolated_app.app.test_client()
    reply=first.post('/bulk_scan',json={'urls':['https://example.com/a','https://example.com/b']})
    assert reply.status_code==200 and reply.json['successful_scans']==2
    assert len(first.get('/get_data').json['data'])==2
    assert second.get('/get_data').json['data']==[]


def test_dashboard_uses_summaries_without_full_features(isolated_app):
    client=isolated_app.app.test_client()
    client.post('/scan',json={'url':'https://example.com'})
    with client.session_transaction() as session:
        owner=session['visitor_id']
    records=isolated_app.store.summaries(owner)
    assert len(records)==1 and 'features' not in records[0] and records[0]['content_status']=='completed'
    assert client.get('/dashboard').status_code==200


def test_production_scan_requires_durable_storage(isolated_app, monkeypatch):
    monkeypatch.setattr(isolated_app,'SERVERLESS',True)
    monkeypatch.setenv('SECRET_KEY','a'*64)
    client=isolated_app.app.test_client()
    response=client.post('/scan',json={'url':'https://example.com'})
    assert response.status_code==503 and response.json['code']=='configuration_required'
    assert client.get('/api/readiness').status_code==503


def test_groq_uses_server_side_strict_schema_and_real_evidence(monkeypatch):
    monkeypatch.setenv('AI_PROVIDER','groq'); monkeypatch.setenv('GROQ_API_KEY','test-not-real')
    f=html_features('<title>Controlled provider fixture</title>'); risk=assess_risk(f)
    response={'assessment':'SAFE','confidence':0.7,'key_reasons':[{'interpretation':'No strong credential collection indicators were observed in the available HTML.','evidence_ids':['html.observed']}],
              'recommended_action':'verify_context','limitations':['Static inspection; missing intelligence is not proof of safety.']}
    def api(method,endpoint,*a,**kw):
        assert endpoint=='https://api.groq.com/openai/v1/chat/completions'
        assert kw['headers']['Authorization']=='Bearer test-not-real'
        assert kw['json']['response_format']['json_schema']['strict']
        reason_schema=kw['json']['response_format']['json_schema']['schema']['properties']['key_reasons']['items']
        assert 'html.observed' in reason_schema['properties']['evidence_ids']['items']['enum']
        assert 'unavailable' not in reason_schema['properties']['evidence_ids']['items']['enum']
        assert 'test-not-real' not in json.dumps(kw['json'])
        return 200,{}, {'choices':[{'finish_reason':'stop','message':{'content':json.dumps(response)}}]}
    monkeypatch.setattr(ai,'api_json',api)
    result=ai.analyze_with_ai(f,risk)
    assert result['status']=='completed' and result['provider']=='groq'
    assert result['key_reasons'][0]['supporting_evidence'][0]['id']=='html.observed'


@pytest.mark.parametrize('reply', [None,{}, {'choices':[]}, {'choices':[{'finish_reason':'length','message':{'content':'{}'}}]}])
def test_groq_incomplete_responses_never_claim_ai(monkeypatch,reply):
    monkeypatch.setenv('AI_PROVIDER','groq'); monkeypatch.setenv('GROQ_API_KEY','test-not-real')
    monkeypatch.setattr(ai,'api_json',lambda *a,**kw:(200,{},reply))
    f=html_features('')
    result=ai.analyze_with_ai(f,assess_risk(f))
    assert result['status']=='invalid_response' and 'confidence' not in result


def test_groq_retries_only_a_short_provider_delay(monkeypatch):
    monkeypatch.setenv('AI_PROVIDER','groq'); monkeypatch.setenv('GROQ_API_KEY','test-not-real')
    f=html_features('<title>Controlled rate-limit fixture</title>'); risk=assess_risk(f)
    response={'assessment':'SAFE','confidence':0.7,'key_reasons':[{'interpretation':'No sensitive inputs were observed in the inspected HTML.','evidence_ids':['html.observed']}],
              'recommended_action':'verify_context','limitations':['Static inspection.']}
    replies=iter([(429,{'Retry-After':'1'},{}),(200,{}, {'choices':[{'finish_reason':'stop','message':{'content':json.dumps(response)}}]})])
    waits=[]
    monkeypatch.setattr(ai,'api_json',lambda *a,**kw:next(replies))
    monkeypatch.setattr(ai.time,'sleep',waits.append)
    assert ai.analyze_with_ai(f,risk)['status']=='completed' and waits==[1]
    monkeypatch.setattr(ai,'api_json',lambda *a,**kw:(429,{'Retry-After':'60'},{}))
    waits.clear()
    assert ai.analyze_with_ai(f,risk)['status']=='rate_limited' and waits==[]


def test_groq_configuration_change_invalidates_cache_fingerprint(monkeypatch):
    old=config_fingerprint()
    monkeypatch.setenv('GROQ_MODEL','controlled-different-model')
    assert config_fingerprint()!=old


def test_postgres_connection_cannot_disable_certificate_verification(monkeypatch):
    import certifi
    import postgres_store
    captured = {}
    calls = []
    class Transaction:
        def __enter__(self): calls.append('transaction entered')
        def __exit__(self, *args): calls.append('transaction exited'); return False
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def transaction(self): return Transaction()
        def execute(self, sql): calls.append(sql)
    def connect(dsn, **options):
        captured.update(options)
        return Connection()
    monkeypatch.setattr(postgres_store.psycopg, 'connect', connect)
    store = postgres_store.PostgresStore.__new__(postgres_store.PostgresStore)
    store.dsn = 'postgresql://user:fixture@db.example.com/phishx?sslmode=disable'
    with store.connection():
        pass
    assert captured['sslmode'] == 'verify-full'
    assert captured['sslrootcert'] == certifi.where()
    assert captured['connect_timeout'] == 3
    assert 'options' not in captured  # PgBouncer rejects startup timeout options.
    assert calls == ['transaction entered', "SET LOCAL statement_timeout = '2s'",
                     "SET LOCAL lock_timeout = '1s'", 'transaction exited']


def test_postgres_failure_keeps_actual_local_evidence(isolated_app):
    import psycopg
    store=isolated_app.store
    class FailingPostgres:
        ready=True
        def available(self):return self.ready
        def save(self,doc):raise psycopg.OperationalError('Controlled outage')
        def failed(self):self.ready=False
    store.postgres=FailingPostgres()
    record={'scan_id':'controlled-pg-fixture','url':'https://example.com/','timestamp':'2026-10-06T00:00:00Z','schema_version':5,'features':{'http':{'status':'completed'}},'evidence':[]}
    store.save(record,owner='visitor-a')
    assert store.get(record['scan_id'],owner='visitor-a')==record
    assert store.get(record['scan_id'],owner='visitor-b') is None
    assert store.mode=='local_sqlite'


def test_readonly_local_storage_returns_real_analysis_with_explicit_failure(isolated_app, monkeypatch):
    import sqlite3
    from contextlib import contextmanager
    @contextmanager
    def readonly():
        raise sqlite3.OperationalError('attempt to write a readonly database')
        yield
    monkeypatch.setattr(isolated_app.store, 'connection', readonly)
    response = isolated_app.app.test_client().post('/scan', json={'url': 'https://example.com/', 'force': True})
    assert response.status_code == 200
    result = response.json
    assert result['features']['http']['status'] == 'completed'
    assert result['storage'] == {'mode': 'unavailable', 'durable': False}
    assert result['state'] == 'partial'
    assert any(item['source'] == 'Storage' and item['status'] == 'unavailable' for item in result['unavailable'])


def test_malformed_html_destinations_are_observed_without_crashing():
    f=html_features('<base href="http://[broken"><form action="https://[broken" method="post"><input type="password"></form>')
    assert f['content']['forms'][0]['actions'][0]['scheme']=='invalid'
    assert any(e['id'].startswith('form.invalid') for e in assess_risk(f)['evidence'])


def test_ai_page_text_reason_has_actual_citable_source():
    f=html_features('<title>Controlled test page</title><p>This is a harmless security demonstration.</p>')
    risk=assess_risk(f)
    text=next(e for e in risk['evidence'] if e['id']=='html.text')
    assert 'harmless security demonstration' in text['detail'] and text['points']==0
    assert 'untrusted' in text['source']
    payload=ai.evidence_payload(f,risk)
    assert any(e['id']=='html.text' for e in payload['evidence'])


def test_bad_origin_and_oversized_requests_reject_before_work(isolated_app):
    client=isolated_app.app.test_client()
    assert client.post('/scan',json={'url':'https://example.com'},headers={'Origin':'https://[malformed'}).status_code==403
    reply=client.post('/scan',data=b'x'*(isolated_app.app.config['MAX_CONTENT_LENGTH']+1),content_type='application/json')
    assert reply.status_code==413


def test_pdf_preserves_unicode_evidence_without_missing_glyphs(isolated_app):
    import io
    from pypdf import PdfReader
    from reports import build_report
    record=isolated_app.app.test_client().post('/scan',json={'url':'https://example.com'}).json
    record['features']['content']['title']='Controlled 安全'
    record['ai']['reason']='A brand\u2011identity limitation; evidence\u2014based analysis.'
    content='\n'.join(page.extract_text() for page in PdfReader(io.BytesIO(build_report(record).getvalue())).pages)
    assert 'brand-identity' in content and 'evidence-based' in content
    assert 'Controlled \\u5b89\\u5168' in content and '\u25a0' not in content


def test_live_updates_are_scoped_to_the_submitting_visitor(isolated_app):
    first,other=isolated_app.app.test_client(),isolated_app.app.test_client()
    first.get('/');other.get('/')
    first_socket=isolated_app.socketio.test_client(isolated_app.app,flask_test_client=first)
    other_socket=isolated_app.socketio.test_client(isolated_app.app,flask_test_client=other)
    try:
        with first.session_transaction() as s:first_owner=s['visitor_id']
        with other.session_transaction() as s:other_owner=s['visitor_id']
        own_sid=next(sid for sid,owner in isolated_app._socket_owners.items() if owner==first_owner)
        foreign_sid=next(sid for sid,owner in isolated_app._socket_owners.items() if owner==other_owner)
        assert first.post('/scan',json={'url':'https://example.com/a','progress_id':foreign_sid}).status_code==200
        assert other_socket.get_received()==[]
        assert first.post('/scan',json={'url':'https://example.com/b','progress_id':own_sid}).status_code==200
        assert any(event['name']=='scan_stage' for event in first_socket.get_received())
        assert other_socket.get_received()==[]
    finally:
        first_socket.disconnect();other_socket.disconnect()
