"""Phish-X AI - existing Flask/Jinja application and route surface."""
from __future__ import annotations

from collections import defaultdict, deque
import concurrent.futures
from datetime import datetime, timedelta, timezone
import json
import hashlib
import logging
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import urlsplit

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / '.env.local')
load_dotenv(Path(__file__).resolve().parent / '.env')
from flask import Flask, jsonify, render_template, request, send_file, session, has_request_context, abort
from flask_socketio import SocketIO
from werkzeug.exceptions import HTTPException

from ai_analysis import analyze_with_ai
from features_extract import analyze_url, extract_content_features, get_dns_record_count, get_certificate_info, same_site
from reports import build_report
from risk_engine import assess_risk, attack_surface, relationship_graph
from secure_fetch import ScanError, normalize_url
from storage import ScanStore, SCHEMA_VERSION
from threat_intelligence import configured_key, set_shared_vt_quota

logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s %(levelname)s %(name)s: %(message)s')
log = logging.getLogger('phish_x')
SERVERLESS = bool(os.getenv('VERCEL'))
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.update(SECRET_KEY=os.getenv('SECRET_KEY') or secrets.token_hex(32), MAX_CONTENT_LENGTH=(4 if SERVERLESS else 16) * 1024 * 1024,
                  MAX_FORM_MEMORY_SIZE=512 * 1024, MAX_FORM_PARTS=20, JSON_SORT_KEYS=False,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=SERVERLESS)
if SERVERLESS:
    app.config['SESSION_COOKIE_NAME'] = '__Host-phishx'
# Same-origin SocketIO only. No background queue, workers, timers, or broadcasting scan data.
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins=None) if not SERVERLESS else None
store = ScanStore()
if SERVERLESS:
    set_shared_vt_quota(lambda limit: store.rate_allowed('virustotal-account', limit))
scan_slots = threading.BoundedSemaphore(3)
upload_slots = threading.BoundedSemaphore(2)
_rate_lock = threading.Lock()
_rate = defaultdict(deque)
_socket_lock = threading.Lock()
_socket_owners = {}


@app.context_processor
def performance_context():
    # Only Production page loads are measured; never local or Preview scans.
    return {'speed_insights_enabled': SERVERLESS and os.getenv('VERCEL_ENV') == 'production'
            and os.getenv('SPEED_INSIGHTS_ENABLED', 'true').lower() in {'true', '1'}}


def visitor_id():
    if not has_request_context():
        return None  # Internal command-line tests only; HTTP callers always get a scope.
    if not re.fullmatch(r'[a-f0-9]{32}', str(session.get('visitor_id', ''))):
        session['visitor_id'] = secrets.token_hex(16)
    return session['visitor_id']


if socketio is not None:
    @socketio.on('connect')
    def connect_scan_progress():
        with _socket_lock:
            _socket_owners[request.sid] = visitor_id()

    @socketio.on('disconnect')
    def disconnect_scan_progress(reason=None):
        with _socket_lock:
            _socket_owners.pop(request.sid, None)


def production_issues(check_connection=False):
    issues = []
    if len(os.getenv('SECRET_KEY', '')) < 32:
        issues.append('Configure a stable random SECRET_KEY of at least 32 characters.')
    if not (store.check_durable_connection() if check_connection else store.durable_available):
        issues.append('Configure a reachable DATABASE_URL (Neon Postgres) or MONGODB_URI for durable scans and reports.')
    return issues


@app.before_request
def guard_requests():
    visitor_id()
    if request.method == 'POST':
        if request.content_length is not None and request.content_length > app.config['MAX_CONTENT_LENGTH']:
            abort(413)
        origin = request.headers.get('Origin')
        try:
            parsed_origin = urlsplit(origin) if origin else None
        except ValueError:
            return jsonify(error='Malformed Origin header.', code='forbidden_origin'), 403
        if parsed_origin and (parsed_origin.netloc != request.host or parsed_origin.scheme != ('https' if SERVERLESS else request.scheme)):
            return jsonify(error='Cross-origin requests are not allowed.', code='forbidden_origin'), 403
        if request.path in {'/scan', '/index', '/bulk_scan', '/extract_features', '/crawl', '/analyze_apk', '/analyze_pdf'}:
            address = request.headers.get('x-vercel-forwarded-for', request.remote_addr or 'unknown').split(',')[0].strip() if SERVERLESS else request.remote_addr or 'unknown'
            now = time.monotonic()
            with _rate_lock:
                for key in list(_rate):
                    if not _rate[key] or _rate[key][-1] < now - 60:
                        del _rate[key]
                entries = _rate[address]
                while entries and entries[0] < now - 60:
                    entries.popleft()
                if len(entries) >= int(os.getenv('SCAN_REQUESTS_PER_MINUTE', '12')):
                    return jsonify(error='Scan request limit reached. Try again in a minute.', code='rate_limited'), 429, {'Retry-After': '60'}
                entries.append(now)
            if SERVERLESS:
                issues = production_issues()
                if issues:
                    return jsonify(error=' '.join(issues), code='configuration_required'), 503
                # Vercel supplies this trusted client-IP header; never trust it locally.
                identity = hashlib.sha256((app.config['SECRET_KEY'] + '|' + address).encode()).hexdigest()
                if not store.rate_allowed(identity, int(os.getenv('SCAN_REQUESTS_PER_MINUTE', '12'))):
                    return jsonify(error='Scan request limit reached. Try again in a minute.', code='rate_limited'), 429, {'Retry-After': '60'}


@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: blob:; connect-src 'self' ws: wss:; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    if not request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'no-store'
    if SERVERLESS:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response


@app.errorhandler(HTTPException)
def http_error(error):
    messages = {413: 'Upload or request exceeds this deployment\'s size limit.', 415: 'Send a JSON object with Content-Type: application/json.', 400: 'Malformed request.', 404: 'Resource not found.'}
    return jsonify(error=messages.get(error.code, error.name), code='http_error'), error.code


@app.errorhandler(Exception)
def unexpected_error(error):
    log.exception('Unhandled application error')
    return jsonify(error='Unexpected server error. Please retry.', code='server_error'), 500


def json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ScanError('Send a JSON object.', 'invalid_input')
    return data


def scan_error_response(error):
    status = 403 if error.code == 'blocked_destination' else 503 if error.code in {'storage_unavailable', 'configuration_required'} else 400
    return jsonify(error=str(error), code=error.code, state='rejected'), status


def summary(result):
    return {key: result.get(key) for key in ('scan_id', 'url', 'title', 'timestamp', 'risk_score', 'severity', 'assessment', 'state', 'is_phishing', 'verdict')}


@app.route('/favicon.ico')
def favicon():
    return send_file(Path(app.root_path) / 'static/images/favicon1.png', mimetype='image/png')


@app.route('/')
@app.route('/index', methods=['GET'])
def home():
    return render_template('index.html', socketio_enabled=socketio is not None)


@app.route('/crawler')
def crawler():
    return render_template('crawler.html', socketio_enabled=socketio is not None)


@app.route('/learn')
def learn():
    return render_template('learn.html')


@app.route('/apk_analyzer')
def apk_analyzer():
    return render_template('apk_analyzer.html', upload_limit_mb=4 if SERVERLESS else 16)


@app.route('/pdf_analyzer')
def pdf_analyzer():
    return render_template('pdf_analyzer.html', upload_limit_mb=4 if SERVERLESS else 16)


@app.route('/api/capabilities')
def capabilities():
    ai_mode = os.getenv('AI_PROVIDER', 'auto').strip().lower()
    ai_configured = (ai_mode in {'auto', 'groq'} and bool(configured_key('GROQ_API_KEY'))) or (ai_mode in {'auto', 'openai'} and bool(configured_key('OPENAI_API_KEY'))) or (ai_mode in {'auto', 'ollama'} and bool(os.getenv('OLLAMA_MODEL')))
    return jsonify(socketio=socketio is not None, storage=store.mode, serverless=SERVERLESS,
                   virustotal_configured=bool(configured_key('VIRUSTOTAL_API_KEY')),
                   safe_browsing_configured=bool(configured_key('SAFE_BROWSING_API_KEY')),
                   ai_configured=bool(ai_configured), ai_provider=ai_mode, bulk_limit=2 if SERVERLESS else 10,
                   upload_limit_mb=4 if SERVERLESS else 16, production_issues=production_issues() if SERVERLESS else [])


@app.route('/api/readiness')
def readiness():
    issues = production_issues(check_connection=True)
    ai_mode = os.getenv('AI_PROVIDER', 'auto').strip().lower()
    if not ((ai_mode in {'auto', 'groq'} and configured_key('GROQ_API_KEY')) or (ai_mode in {'auto', 'openai'} and configured_key('OPENAI_API_KEY')) or (ai_mode in {'auto', 'ollama'} and os.getenv('OLLAMA_MODEL'))):
        issues.append('Configure a supported AI provider and server-side key/model.')
    return jsonify(ready=not issues, issues=issues, storage=store.mode), 503 if issues else 200


def get_cached_result(url):
    return store.cached(normalize_url(url), owner=visitor_id())


def process_url(url: str, progress_id=None, force=False, owner=None):
    url = normalize_url(url)
    if owner is None:
        owner = visitor_id()
    if progress_id is not None and (not isinstance(progress_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{10,100}', progress_id)):
        raise ScanError('Invalid scan progress identifier.', 'invalid_input')
    if progress_id is not None:
        with _socket_lock:
            if not owner or _socket_owners.get(progress_id) != owner:
                progress_id = None  # A stale/foreign live connection falls back to HTTP.
    if SERVERLESS:
        issues = production_issues()
        if issues:
            raise ScanError(' '.join(issues), 'configuration_required')
    cached = None if force else store.cached(url, owner=owner)
    if cached:
        return cached
    if not scan_slots.acquire(blocking=False):
        raise ScanError('Scanner is busy. Retry shortly.', 'busy')
    start = time.monotonic()
    deadline = start + 48  # Leave room for persistence and response serialization under Vercel's 60s limit.
    timeline = []
    def event(stage, status='completed', detail=''):
        step = {'stage': stage, 'status': status, 'detail': str(detail)[:1000],
                'timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds'), 'elapsed_ms': round((time.monotonic() - start) * 1000)}
        timeline.append(step)
        if socketio is not None and progress_id and re.fullmatch(r'[A-Za-z0-9_-]{10,100}', progress_id):
            socketio.emit('scan_stage', step, to=progress_id)
    try:
        event('URL received', detail=url)
        features = analyze_url(url, event, deadline - 14)
        risk = assess_risk(features)
        event('Risk engine calculated', detail=f"{risk['score']}/100; {risk['assessment']}; {len(risk['evidence'])} evidence records")
        ai = analyze_with_ai(features, risk, deadline)
        event('AI evidence reasoning', ai['status'], ai.get('reason') or f"{ai['provider']}/{ai['model']}; evidence references validated")
        if ai['status'] != 'completed':
            risk['unavailable'].append({'source': 'AI reasoning', 'status': ai['status'], 'reason': ai.get('reason', 'No AI assessment available.')})
            if risk['state'] == 'completed':
                risk['state'] = 'partial'
        event('Final assessment', risk['state'], f"{risk['assessment']}; observed score {risk['score']}/100")
        result = {'schema_version': SCHEMA_VERSION, 'scan_id': str(uuid.uuid4()), 'url': url,
                  'timestamp': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'title': features.get('content', {}).get('title') or url,
                  'features': features, 'risk_score': risk['score'], 'severity': risk['severity'], 'assessment': risk['assessment'],
                  'verdict': risk['assessment'] + (' - analysis incomplete' if risk['state'] != 'completed' else ''),
                  'state': risk['state'], 'recommendation': risk['recommendation'], 'score_note': risk['score_note'],
                  'is_phishing': risk['score'] >= 30, 'evidence': risk['evidence'], 'unavailable': risk['unavailable'],
                  'phishing_dna': risk['dna'], 'attack_surface': attack_surface(features), 'threat_graph': relationship_graph(features, risk),
                  'timeline': timeline, 'ai': ai, 'cached': False, 'duration_ms': round((time.monotonic() - start) * 1000)}
        store.save(result, owner=owner)
        return result
    finally:
        scan_slots.release()


@app.route('/scan', methods=['POST'])
@app.route('/index', methods=['POST'])
@app.route('/extract_features', methods=['POST'])
def scan():
    try:
        data = json_body()
        # Deliberately ignore title/content/is_phishing/security scores from clients.
        result = process_url(data.get('url'), data.get('progress_id'), force=data.get('force') is True)
        return jsonify(result)
    except ScanError as error:
        if error.code == 'busy':
            return jsonify(error=str(error), code='busy'), 429
        return scan_error_response(error)


@app.route('/bulk_scan', methods=['POST'])
def bulk_scan():
    try:
        data = json_body()
        urls = data.get('urls')
        limit = 2 if SERVERLESS else 10
        if not isinstance(urls, list) or not urls or len(urls) > limit or not all(isinstance(u, str) for u in urls):
            raise ScanError(f'Provide a list of 1-{limit} URL strings.', 'invalid_input')
        def one(url):
            try:
                return process_url(url, force=data.get('force') is True, owner=owner), None
            except ScanError as error:
                return None, {'url': url[:4096], 'error': str(error), 'code': error.code}
            except Exception:
                log.exception('Bulk URL analysis failed')
                return None, {'url': url[:4096], 'error': 'Unexpected scan error.', 'code': 'server_error'}
        results, errors = [], []
        owner = visitor_id()  # Flask's request context is not available inside worker threads.
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            # map preserves input order; each scan owns its evidence and bounded time budget.
            for result, error in executor.map(one, urls):
                if result:
                    results.append(result)
                else:
                    errors.append(error)
        cached = sum(bool(r['cached']) for r in results)
        return jsonify(results=results, errors=errors, total_scanned=len(urls), successful_scans=len(results), failed_scans=len(errors),
                       cached_results=cached, new_scans=len(results) - cached, suspicious_count=sum(r['risk_score'] >= 30 for r in results),
                       safe_count=sum(r['assessment'] in {'SAFE', 'LOW'} and r['features']['content']['status'] in {'completed', 'partial'} for r in results),
                       partial_count=sum(r['state'] != 'completed' for r in results))
    except ScanError as error:
        return scan_error_response(error)


@app.route('/get_data')
def get_data():
    return jsonify(data=[summary(r) for r in reversed(store.summaries(visitor_id(), 50))], storage=store.mode, message='Actual scans for this browser session')


@app.route('/crawl', methods=['POST'])
def crawl_site():
    try:
        data = json_body()
        if SERVERLESS and data.get('follow_links') is True:
            raise ScanError('Linked-page crawling requires a persistent local/server deployment. Vercel analyzes one submitted page per request.', 'serverless_limit')
        seed = process_url(data.get('url'), data.get('progress_id'), force=data.get('force') is True)
        results, errors = [seed], []
        if data.get('follow_links') is True:
            final = seed['features']['http'].get('final_url') or seed['url']
            seen = {seed['url'], final}
            selected = []
            for link in seed['features']['content'].get('links', []):
                if link['scheme'] not in {'http', 'https'} or not same_site(link['hostname'], urlsplit(final).hostname):
                    continue
                try:
                    url = normalize_url(link['url'])
                except ScanError:
                    continue
                # Avoid automatic submission/search/logout endpoints and arbitrary query URLs.
                if url in seen or urlsplit(url).query or re.search(r'(?:logout|signout|delete|unsubscribe)', urlsplit(url).path, re.I):
                    continue
                seen.add(url)
                selected.append(url)
                if len(selected) == 2:
                    break
            for url in selected:
                try:
                    results.append(process_url(url, data.get('progress_id')))
                except ScanError as error:
                    errors.append({'url': url, 'error': str(error), 'code': error.code})
        return jsonify(results=results, errors=errors, followed_pages=len(results) - 1, serverless=SERVERLESS)
    except ScanError as error:
        return scan_error_response(error)


@app.route('/api/scans/<scan_id>')
def stored_scan(scan_id):
    if not re.fullmatch(r'[a-f0-9-]{36}', scan_id):
        return jsonify(error='Invalid scan ID.'), 400
    result = store.get(scan_id, owner=visitor_id())
    return jsonify(result) if result else (jsonify(error='Scan result not found or no longer available.'), 404)


@app.route('/download_report', methods=['GET', 'POST'])
def download_report():
    try:
        data = dict(request.args) if request.method in {'GET', 'HEAD'} else json_body()
        if isinstance(data.get('scan_id'), str):
            result = store.get(data['scan_id'], owner=visitor_id())
        elif isinstance(data.get('url'), str):
            result = store.latest_url(normalize_url(data['url']), owner=visitor_id())
        else:
            raise ScanError('Provide the completed scan ID.', 'invalid_input')
        if result is None:
            return jsonify(error='Stored scan not found. Complete a scan before downloading its report.', code='scan_not_found'), 409
        if request.method == 'HEAD':
            return '', 200, {'Content-Type': 'application/pdf'}
        return send_file(build_report(result), mimetype='application/pdf', as_attachment=True, download_name=f"phish-x-ai-{result['scan_id'][:8]}.pdf")
    except ScanError as error:
        return scan_error_response(error)


@app.route('/dashboard')
def dashboard():
    records = store.summaries(visitor_id(), 10000)
    safe = [r for r in records if r['assessment'] in {'SAFE', 'LOW'} and r['content_status'] in {'completed', 'partial'}]
    suspicious = [r for r in records if r['risk_score'] >= 30]
    dates = [(datetime.now(timezone.utc) - timedelta(days=i)).date().isoformat() for i in range(6, -1, -1)]
    return render_template('dashboard.html', total_sites=len(records), safe_sites=len(safe), phishing_sites=len(suspicious),
                           unknown_sites=len(records) - len(safe) - len(suspicious), partial_sites=sum(r['state'] != 'completed' for r in records),
                           phishing_rate=round(100 * len(suspicious) / len(records), 1) if records else 0,
                           top_phishing_domains=[{'url': r['url'], 'detection_date': r['timestamp'], 'confidence_score': r['risk_score'], 'assessment': r['assessment']} for r in sorted(suspicious, key=lambda r: r['risk_score'], reverse=True)[:10]],
                           recent_activity=[{**summary(r), 'details': r['state']} for r in records[:10]], dates=dates,
                           safe_trend=[sum(r['timestamp'].startswith(day) for r in safe) for day in dates],
                           phishing_trend=[sum(r['timestamp'].startswith(day) for r in suspicious) for day in dates], storage_mode=store.mode)


def analyze_upload(kind):
    if not upload_slots.acquire(blocking=False):
        return jsonify(error='File analyzer is busy. Retry shortly.', code='busy'), 429
    try:
        return _analyze_upload(kind)
    finally:
        upload_slots.release()


def _analyze_upload(kind):
    file = request.files.get(kind)
    if file is None or not file.filename:
        return jsonify(error=f'Select a {kind.upper()} file.'), 400
    if not file.filename.lower().endswith('.' + kind):
        return jsonify(error=f'Only .{kind} files are accepted by this analyzer.'), 400
    # Unique temporary directory per request; never reuse user-controlled filenames.
    with tempfile.TemporaryDirectory(prefix='phish-x-', dir='/tmp') as directory:
        path = Path(directory) / ('upload.' + kind)
        file.save(path)
        with path.open('rb') as stream:
            magic = stream.read(8)
        if not path.stat().st_size or (kind == 'pdf' and not magic.startswith(b'%PDF-')) or (kind == 'apk' and not magic.startswith(b'PK')):
            return jsonify(error='File content does not match the selected file type.'), 400
        try:
            worker = subprocess.run([sys.executable, str(Path(__file__).parent / 'file_analysis.py'), kind, str(path)], capture_output=True, text=True, timeout=16)
            if worker.returncode < 0:
                return jsonify(error='File analysis exceeded its resource limits.', code='resource_limit', status='partial'), 422
            data = json.loads(worker.stdout)
            if worker.returncode:
                return jsonify(data), 503 if data.get('code') == 'dependency_unavailable' else 422
            return jsonify(data)
        except subprocess.TimeoutExpired:
            return jsonify(error='File analysis exceeded its processing time limit.', code='timeout', status='timeout'), 408
        except (OSError, ValueError):
            log.warning('Upload worker unavailable or returned invalid output')
            return jsonify(error='File analyzer is unavailable in this deployment.', code='analyzer_unavailable'), 503


@app.route('/analyze_apk', methods=['POST'])
def analyze_apk():
    return analyze_upload('apk')


@app.route('/analyze_pdf', methods=['POST'])
def analyze_pdf():
    return analyze_upload('pdf')


# Compatibility helpers are real; main scan reuses one analysis instead of calling them repeatedly.
def check_content(url):
    return extract_content_features(url)


def check_dns(url):
    return get_dns_record_count(url)


def check_ssl(url):
    return get_certificate_info(url)


def analyze_url_parallel(url):
    return analyze_url(url)


if __name__ == '__main__':
    config = dict(host=os.getenv('FLASK_HOST', '127.0.0.1'), port=int(os.getenv('FLASK_PORT', '5001')),
                  debug=os.getenv('FLASK_DEBUG', 'False').lower() in {'true', '1'}, use_reloader=False)
    if socketio is not None:
        socketio.run(app, **config, allow_unsafe_werkzeug=True)
    else:
        app.run(**config)
