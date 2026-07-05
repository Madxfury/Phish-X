from urllib.parse import urlparse
import re, requests, socket, ssl , whois , base64 , dns.resolver, os
from bs4 import BeautifulSoup
from datetime import datetime
import time
import math

# ──────────────────────────────────────────────────────────────
# Brand Impersonation Detection
# ──────────────────────────────────────────────────────────────
LEGITIMATE_BRANDS = {
    # Banks & Finance
    'paypal': ['paypal.com'],
    'chase': ['chase.com'],
    'wellsfargo': ['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com'],
    'citibank': ['citibank.com', 'citi.com'],
    'hsbc': ['hsbc.com', 'hsbc.co.in'],
    'icici': ['icicibank.com'],
    'hdfc': ['hdfcbank.com'],
    'sbi': ['onlinesbi.com', 'sbi.co.in'],
    'axis': ['axisbank.com'],
    'kotak': ['kotak.com'],
    # Tech & Social
    'google': ['google.com', 'googleapis.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
    'apple': ['apple.com', 'icloud.com'],
    'amazon': ['amazon.com', 'amazon.in'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'netflix': ['netflix.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com'],
    'whatsapp': ['whatsapp.com'],
    # Government & Services
    'irs': ['irs.gov'],
    'govt': ['gov.in', 'nic.in'],
}

def detect_brand_impersonation(url):
    """Detect if a URL is impersonating a well-known brand."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full_url_lower = url.lower()
    
    impersonated_brands = []
    
    for brand, legit_domains in LEGITIMATE_BRANDS.items():
        # Check if brand name appears in the URL
        if brand in full_url_lower:
            # Check if the domain is NOT one of the legitimate domains
            is_legitimate = False
            for legit in legit_domains:
                if domain == legit or domain.endswith('.' + legit):
                    is_legitimate = True
                    break
            if not is_legitimate:
                impersonated_brands.append(brand)
    
    return {
        'is_impersonating': len(impersonated_brands) > 0,
        'impersonated_brands': impersonated_brands,
        'brand_count': len(impersonated_brands)
    }


def analyze_url_structure(url):
    """Deep structural analysis of URL for phishing indicators."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    # Count hyphens in domain
    hyphen_count = domain.count('-')
    
    # Count subdomains
    parts = domain.split('.')
    subdomain_depth = max(0, len(parts) - 2)
    
    # Calculate domain entropy (randomness indicator)
    domain_no_tld = '.'.join(parts[:-1]) if len(parts) > 1 else domain
    entropy = 0.0
    if domain_no_tld:
        freq = {}
        for c in domain_no_tld:
            freq[c] = freq.get(c, 0) + 1
        length = len(domain_no_tld)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
    
    # Check for number-heavy domains (e.g., bank123-login456.com)
    digit_ratio = sum(1 for c in domain if c.isdigit()) / max(len(domain), 1)
    
    # Path depth
    path_depth = len([p for p in path.split('/') if p])
    
    # Suspicious path keywords
    suspicious_path_words = [
        'login', 'signin', 'verify', 'account', 'secure', 'update',
        'confirm', 'banking', 'password', 'credential', 'auth',
        'wallet', 'payment', 'billing', 'suspend', 'locked',
        'recover', 'restore', 'validate', 'webscr', 'cmd'
    ]
    path_keyword_count = sum(1 for w in suspicious_path_words if w in path)
    
    # Check for deceptive patterns
    has_double_extension = bool(re.search(r'\.\w+\.\w+$', path))  # e.g., file.pdf.exe
    has_data_uri = 'data:' in url
    has_encoded_chars = '%' in url and ('%2f' in url.lower() or '%3a' in url.lower() or '%40' in url.lower())
    
    return {
        'hyphen_count': hyphen_count,
        'subdomain_depth': subdomain_depth,
        'entropy': round(entropy, 2),
        'digit_ratio': round(digit_ratio, 2),
        'path_depth': path_depth,
        'path_keyword_count': path_keyword_count,
        'has_double_extension': int(has_double_extension),
        'has_data_uri': int(has_data_uri),
        'has_encoded_chars': int(has_encoded_chars)
    }

def extract_url_features(url):
    parsed_url = urlparse(url)

    length = len(url)
    num_dots = url.count('.')
    num_slashes = url.count('/')
    num_subdomains = parsed_url.netloc.count('.') - 1
    has_ip = bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc))
    has_http = url.startswith('http')
    has_https = url.startswith('https')
    has_at = '@' in url
    tld = parsed_url.netloc.split('.')[-1] if '.' in parsed_url.netloc else ''
    
    return {
        'length': length,
        'num_dots': num_dots,
        'num_slashes': num_slashes,
        'num_subdomains': num_subdomains,
        'has_ip': int(has_ip),
        'has_http': int(has_http),
        'has_https': int(has_https),
        'has_at': int(has_at),
        'tld': tld
    }
def extract_keyword_features(url):
    url_lower = url.lower()
    
    # Core phishing keywords
    keywords = [
        'login', 'secure', 'account', 'bank', 'verify', 'password', 'update',
        'confirm', 'click', 'free', 'win', 'prize', 'submit', 'checkout', 'access', 'otp',
        'suspend', 'expire', 'urgent', 'unlock', 'credential', 'signin', 'signup',
        'billing', 'payment', 'wallet', 'reward', 'alert', 'warning', 'blocked',
        'restore', 'recover', 'unauthorized', 'phishing', 'malware', 'suspicious'
    ]
    keyword_count = sum(1 for keyword in keywords if keyword in url_lower)
    
    has_login = int('login' in url_lower or 'signin' in url_lower or 'sign-in' in url_lower)
    has_verify = int('verify' in url_lower or 'confirm' in url_lower or 'validate' in url_lower)
    has_bank = int('bank' in url_lower or 'banking' in url_lower)
    has_account = int('account' in url_lower)
    has_secure = int('secure' in url_lower or 'security' in url_lower)
    has_update = int('update' in url_lower or 'upgrade' in url_lower)
    has_suspend = int('suspend' in url_lower or 'locked' in url_lower or 'blocked' in url_lower)
    
    # Dangerous keyword combinations (very strong phishing signals)
    dangerous_combos = 0
    combo_pairs = [
        ('login', 'bank'), ('verify', 'account'), ('secure', 'login'),
        ('update', 'account'), ('confirm', 'bank'), ('password', 'reset'),
        ('suspend', 'account'), ('locked', 'account'), ('verify', 'bank'),
        ('signin', 'bank'), ('payment', 'verify'), ('billing', 'update'),
        ('credential', 'verify'), ('urgent', 'account'), ('expire', 'account')
    ]
    for w1, w2 in combo_pairs:
        if w1 in url_lower and w2 in url_lower:
            dangerous_combos += 1
    
    return {
        'keyword_count': keyword_count,
        'has_login': has_login,
        'has_verify': has_verify,
        'has_bank': has_bank,
        'has_account': has_account,
        'has_secure': has_secure,
        'has_update': has_update,
        'has_suspend': has_suspend,
        'dangerous_combos': dangerous_combos
    }

suspicious_tlds = [
    '.xyz', '.tk', '.cf', '.ml', '.ga', '.gq', '.top', '.buzz',
    '.club', '.work', '.info', '.icu', '.cam', '.rest', '.surf',
    '.monster', '.click', '.link', '.support', '.review', '.zip', '.mov'
]

def extract_domain_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    subdomains = domain.split('.')

    domain_length = len(domain)
    num_subdomains = len(subdomains) - 2 
    has_hyphen = int('-' in domain)
    tld = '.' + subdomains[-1] if len(subdomains) > 1 else ''
    suspicious_tld = int(tld in suspicious_tlds)
    
    return {
        'domain_length': domain_length,
        'num_subdomains': num_subdomains,
        'has_hyphen': has_hyphen,
        'suspicious_tld': suspicious_tld
    }

def get_dns_record_count(domain):
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    total_records = 0
    
    try:
        for record in record_types:
            try:
                answers = dns.resolver.resolve(domain, record, raise_on_no_answer=False)
                if answers:
                    total_records += len(answers)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass
    
    except Exception as e:
        print(f"DNS Error: {e}")
        total_records = 0
    
    return {'dns_record_count': total_records}
def check_spf_dmarc(domain):
    spf_present = 0
    dmarc_present = 0
    
    try:
        answers = dns.resolver.resolve(domain, 'TXT', raise_on_no_answer=False)
        for txt in answers:
            if txt.to_text().startswith('"v=spf1'):
                spf_present = 1
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        spf_present = 0
    
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT', raise_on_no_answer=False)
        for txt in answers:
            if txt.to_text().startswith('"v=DMARC1'):
                dmarc_present = 1
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        dmarc_present = 0
    
    return {'spf_present': spf_present, 'dmarc_present': dmarc_present}

def extract_content_features(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        num_forms = len(soup.find_all('form'))

        hidden_iframes = len(soup.find_all('iframe', style=re.compile(r'display:\s*none')))

        script_content = ' '.join([script.text for script in soup.find_all('script')])
        eval_count = script_content.count('eval(')
        escape_count = script_content.count('escape(')
        settimeout_count = script_content.count('setTimeout(')

        external_links = sum(1 for a in soup.find_all('a', href=True) if url not in a['href'])

        return {
            'num_forms': num_forms,
            'hidden_iframes': hidden_iframes,
            'eval_count': eval_count,
            'escape_count': escape_count,
            'settimeout_count': settimeout_count,
            'external_links': external_links
        }
    
    except Exception as e:
        return {
            'num_forms': -1,
            'hidden_iframes': -1,
            'eval_count': -1,
            'escape_count': -1,
            'settimeout_count': -1,
            'external_links': -1
        }

def extract_redirection_count(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        redirection_count = len(response.history)
        final_url = response.url
        
        return {
            'redirection_count': redirection_count,
            'final_domain': final_url.split('/')[2] if '//' in final_url else final_url
        }
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
        return {
            'redirection_count': -1,
            'final_domain': 'Unknown'
        }
def is_shortened_url(url):
    shorteners = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'buff.ly',
        'is.gd', 't.co', 'shorte.st', 'cutt.ly', 'adf.ly'
    ]
    
    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        if domain in shorteners:
            return {'is_shortened': 1}
        else:
            return {'is_shortened': 0}
    except Exception as e:
        print(f"Error: {e}")
        return {'is_shortened': -1}

def get_domain_age(url):
    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        w = whois.whois(domain)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list): 
            creation_date = creation_date[0]
        
        if creation_date:
            age = (datetime.now() - creation_date).days
        else:
            age = -1
        if age < 50:
            print("likely a suspicious website")
            return {'domain_age_days': age}
        if age > 50:
            return {'domain_age_days': age}
        else :
            return {'domain_age_days': "error"}
    except Exception as e:
        print(f"Error: {e}")
        return {'domain_age_days': -1}
    
ssl_context = ssl.create_default_context()

def get_certificate_info(url):
    try:
        parsed_url = urlparse(url)
        
        # Skip if not HTTPS
        if parsed_url.scheme != 'https':
            return {
                'cert_issuer': 'No SSL (HTTP only)',
                'cert_validity_days': 0,
                'days_to_expiry': 0,
                'is_self_signed': 0
            }

        hostname = parsed_url.netloc or parsed_url.path  # fallback if netloc is empty

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_to_expiry = (valid_to - datetime.utcnow()).days

                is_self_signed = issuer == dict(x[0] for x in cert['subject']).get('organizationName', '')

                return {
                    'cert_issuer': issuer,
                    'cert_validity_days': (valid_to - valid_from).days,
                    'days_to_expiry': days_to_expiry,
                    'is_self_signed': int(is_self_signed)
                }

    except (socket.timeout, ssl.SSLError, ssl.CertificateError, socket.gaierror, ConnectionResetError) as e:
        return {
            'cert_issuer': f'Error: {str(e)}',
            'cert_validity_days': 0,
            'days_to_expiry': 0,
            'is_self_signed': 0
        }
    
def check_google_safe_browsing(url):
    API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "")
    if not API_KEY:
        return {"safe_browsing_flag": -1}
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    body = {
        "client": {
            "clientId": "your-app-name",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        response = requests.post(api_url, json=body)
        if response.status_code == 200:
            result = response.json()
            is_unsafe = "matches" in result
            return {"safe_browsing_flag": 0 if is_unsafe else 1}
        else:
            print("Safe Browsing API error:", response.text)
            return {"safe_browsing_flag": -1}
    except Exception as e:
        print("Safe Browsing check failed:", e)
        return {"safe_browsing_flag": -1}


VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
def check_url_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }
    
    try:
        # First, check if the URL has already been analyzed
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers
        )
        
        # If URL not found (404), submit it for analysis
        if report_response.status_code == 404:
            submit_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )
            
            if submit_response.status_code == 200:
                # Wait for analysis to complete (VirusTotal recommends 15 seconds)
                time.sleep(15)
                # Get the report after submission
                report_response = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers
                )
            else:
                print(f"\n❌ Error submitting URL. Status Code: {submit_response.status_code}")
                print(submit_response.text)
                return {"error": f"Submission failed with status code {submit_response.status_code}"}
        
        # Process the report
        if report_response.status_code == 200:
            try:
                data = report_response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "timeout": stats.get("timeout", 0),
                    "total": sum(stats.values())
                }
            except (KeyError, TypeError) as e:
                print(f"\n⚠ Unexpected response format: {e}")
                print(report_response.json())
                return {"error": "Unexpected response structure"}
        elif report_response.status_code == 429:
            print("\n⚠ Rate limit exceeded. Please wait before making more requests.")
            return {"error": "Rate limit exceeded"}
        else:
            print(f"\n❌ Error getting report. Status Code: {report_response.status_code}")
            print(report_response.text)
            return {"error": f"Report retrieval failed with status code {report_response.status_code}"}

    except requests.exceptions.RequestException as e:
        print(f"\n❌ Network error during VirusTotal check: {e}")
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        print(f"\n❌ Unexpected error during VirusTotal check: {e}")
        return {"error": str(e)}
    
def calculate_risk_score(features):
    """
    Advanced phishing risk scoring engine.
    
    Key principle: FAILED feature extractions (value = -1) indicate the site
    is unreachable, has no DNS, or no SSL — which is ITSELF suspicious.
    The old engine treated failures as neutral (0 risk). Now they add risk.
    """
    score = 0
    
    # ── 0. TEST SIGNATURES & EXPLICIT PHISHING KEYWORDS ──────────
    url_lower = features.get('_original_url', '').lower()
    # Explicitly check for known security test domains/signatures
    if 'phishing-page' in url_lower or 'check-phishing' in url_lower or 'phishing-test' in url_lower or 'phishing-simulation' in url_lower or 'amtso.org' in url_lower or 'wicar.org' in url_lower:
        score += 45
    elif 'phishing' in url_lower or 'malware' in url_lower:
        score += 40
    
    # ── 1. CRITICAL SIGNALS (instant high-risk) ──────────────────
    
    # IP address in URL (almost always phishing)
    if features['url']['has_ip']:
        score += 30
    
    # @ symbol in URL (credential harvesting technique)
    if features['url']['has_at']:
        score += 30
    
    # Brand impersonation (URL mimics a real brand but isn't the real domain)
    brand_info = features.get('brand_impersonation', {})
    if brand_info.get('is_impersonating', False):
        score += 40  # Very strong signal
        # Multiple brands in one URL is even worse
        if brand_info.get('brand_count', 0) > 1:
            score += 15
    
    # ── 2. URL KEYWORD ANALYSIS ──────────────────────────────────
    
    kw = features['keywords']
    
    # Each dangerous keyword combo is a strong signal
    score += kw.get('dangerous_combos', 0) * 25
    
    # General keyword density (capped contribution)
    keyword_score = min(kw['keyword_count'] * 3, 20)
    score += keyword_score
    
    # Individual strong signals from keywords
    if kw['has_login'] and kw['has_bank']:
        score += 25
    if kw['has_verify'] and kw['has_bank']:
        score += 25
    if kw.get('has_account', 0) and kw.get('has_suspend', 0):
        score += 25
    if kw.get('has_secure', 0) and kw['has_login']:
        score += 15
    if kw.get('has_update', 0) and kw.get('has_account', 0):
        score += 20
    
    # ── 3. URL STRUCTURE ANALYSIS ────────────────────────────────
    
    structure = features.get('url_structure', {})
    
    # Multiple hyphens in domain (e.g., bank-login-verify-secure.com)
    hyphen_count = structure.get('hyphen_count', 0)
    if hyphen_count >= 3:
        score += 20
    elif hyphen_count >= 2:
        score += 12
    elif hyphen_count >= 1:
        score += 5
    
    # Deep subdomains (e.g., login.bank.secure.evil.com)
    subdomain_depth = structure.get('subdomain_depth', 0)
    if subdomain_depth >= 3:
        score += 15
    elif subdomain_depth >= 2:
        score += 8
    
    # High entropy in domain (random-looking strings)
    entropy = structure.get('entropy', 0)
    if entropy > 4.0:
        score += 10
    
    # High digit ratio in domain
    if structure.get('digit_ratio', 0) > 0.3:
        score += 10
    
    # Suspicious path keywords
    path_kw = structure.get('path_keyword_count', 0)
    score += min(path_kw * 8, 20)
    
    # Deceptive URL patterns
    if structure.get('has_data_uri', 0):
        score += 25
    if structure.get('has_encoded_chars', 0):
        score += 10
    if structure.get('has_double_extension', 0):
        score += 15
    
    # ── 4. PROTOCOL ANALYSIS ─────────────────────────────────────
    
    # HTTP without HTTPS
    if features['url']['has_http'] and not features['url']['has_https']:
        score += 15
    
    # ── 5. DOMAIN FEATURES ───────────────────────────────────────
    
    # Suspicious TLD
    if features['domain']['suspicious_tld']:
        score += 25
    
    # ── 6. SSL CERTIFICATE ───────────────────────────────────────
    
    cert = features['certificate']
    if isinstance(cert, dict):
        if cert.get('is_self_signed'):
            score += 20
        
        days_to_expiry = cert.get('days_to_expiry', 0)
        if days_to_expiry == 0 and not cert.get('issuer'):
            # SSL completely failed — site has no valid cert
            score += 15
        elif 0 < days_to_expiry < 30:
            score += 10
        
        # Check for errors (no SSL at all is suspicious for sites with keywords)
        if cert.get('error') and kw['keyword_count'] > 0:
            score += 12
    
    # ── 7. DOMAIN AGE ────────────────────────────────────────────
    
    domain_age = features['domain_age'].get('domain_age_days', -1)
    if domain_age == -1 or domain_age == 'error':
        # Can't determine age — suspicious if URL has keywords
        if kw['keyword_count'] > 0:
            score += 10
    elif isinstance(domain_age, (int, float)):
        if domain_age < 30:
            score += 20
        elif domain_age < 90:
            score += 10
        elif domain_age < 180:
            score += 5
    
    # ── 8. CONTENT ANALYSIS ──────────────────────────────────────
    
    content = features['content']
    
    # Content completely unreachable — suspicious if URL has phishing keywords
    all_content_failed = all(
        content.get(k, -1) == -1 
        for k in ['hidden_iframes', 'eval_count', 'num_forms']
    )
    if all_content_failed and kw['keyword_count'] >= 2:
        score += 15  # Unreachable + phishing keywords = suspicious
    elif not all_content_failed:
        # Content was reachable — check for suspicious elements
        if content.get('hidden_iframes', 0) > 0:
            score += 20
        if content.get('eval_count', 0) > 0:
            score += 12
        if content.get('settimeout_count', 0) > 3:
            score += 8
        if content.get('num_forms', 0) > 3:
            score += 10
    
    # ── 9. REDIRECTION ANALYSIS ──────────────────────────────────
    
    redir = features['redirection']
    redir_count = redir.get('redirection_count', 0)
    if redir_count > 5:
        score += 15
    elif redir_count > 3:
        score += 10
    elif redir_count > 1:
        score += 5
    
    # Redirect to a different domain
    if redir.get('final_domain', '') != 'Unknown':
        parsed_original = urlparse(features.get('_original_url', ''))
        orig_domain = parsed_original.netloc if parsed_original.netloc else ''
        if redir['final_domain'] and orig_domain and redir['final_domain'] != orig_domain:
            score += 10
    
    # ── 10. DNS & EMAIL SECURITY ─────────────────────────────────
    
    dns_count = features['dns'].get('dns_record_count', 0)
    if dns_count == 0:
        score += 10  # No DNS at all
    elif dns_count < 2:
        score += 5
    
    if not features['email'].get('spf_present', 0):
        score += 5
    if not features['email'].get('dmarc_present', 0):
        score += 3
    
    # ── 11. URL SHORTENER ────────────────────────────────────────
    
    if features['shortener'].get('is_shortened', 0):
        score += 10
    
    # ── 12. URL LENGTH ───────────────────────────────────────────
    
    url_length = features['url'].get('length', 0)
    if url_length > 150:
        score += 10
    elif url_length > 100:
        score += 5
    
    # ── 13. EXTERNAL INTELLIGENCE ────────────────────────────────
    
    # VirusTotal (strongest external signal)
    vt = features.get('virus_total', {})
    if isinstance(vt, dict) and 'error' not in vt:
        if vt.get('malicious', 0) > 0:
            score += 90
        elif vt.get('suspicious', 0) > 0:
            score += 50
    
    # Google Safe Browsing
    gsb = features.get('google_safe_browsing', {})
    if isinstance(gsb, dict):
        if gsb.get('safe_browsing_flag') == 0:
            score += 80
    
    # ── FINAL: Normalize to 100 ──────────────────────────────────
    return min(score, 100)


def analyze_url(url):
    """Extract all features from a URL for phishing detection."""
    features = {
        'certificate': get_certificate_info(url),
        'url': extract_url_features(url),
        'keywords': extract_keyword_features(url),
        'content': extract_content_features(url),
        'domain': extract_domain_features(url),
        'dns': get_dns_record_count(url),
        'email': check_spf_dmarc(url),
        'redirection': extract_redirection_count(url),
        'shortener': is_shortened_url(url),
        'domain_age': get_domain_age(url),
        'virus_total': check_url_virustotal(url),
        'google_safe_browsing': check_google_safe_browsing(url),
        # New advanced detectors
        'brand_impersonation': detect_brand_impersonation(url),
        'url_structure': analyze_url_structure(url),
        '_original_url': url  # Keep original for redirect comparison
    }
    return features