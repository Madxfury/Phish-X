"""Phish-X URL, domain and content extraction; one verified crawl per analysis."""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import math
import os
import re
import time
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

from bs4 import BeautifulSoup
import dns.resolver
import dns.exception
import tldextract

from secure_fetch import ScanError, fetch_website, normalize_url, resolve_target, public_ip
from threat_intelligence import check_url_virustotal, check_google_safe_browsing

_SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_SITE_SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

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


def registered_domain(host: str) -> str:
    parts = _SUFFIXES(host or "")
    return parts.top_domain_under_public_suffix or host


def same_site(a: str, b: str) -> bool:
    # Hosted tenants (for example user.github.io) are separate sites, even when
    # their provider shares one public registrable domain.
    def site(host):
        parts = _SITE_SUFFIXES(host or "")
        return parts.top_domain_under_public_suffix or host
    return site(a) == site(b)


def entropy(value: str) -> float:
    return round(-sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values()), 3) if value else 0.0


def extract_url_features(url: str) -> dict:
    p = urlsplit(url)
    host = p.hostname or ""
    domain = _SUFFIXES(host)
    try:
        ipaddress.ip_address(host)
        has_ip = True
    except ValueError:
        has_ip = False
    query = parse_qsl("&".join(p.query.split("&")[:200]), keep_blank_values=True, max_num_fields=200)
    return {"length": len(url), "num_dots": url.count("."), "num_slashes": url.count("/"),
            "num_subdomains": len(domain.subdomain.split(".")) if domain.subdomain else 0,
            "has_ip": has_ip, "has_http": p.scheme == "http", "has_https": p.scheme == "https", "has_at": "@" in url,
            "tld": domain.suffix, "hostname": host, "path_depth": len([s for s in p.path.split("/") if s]),
            "query_count": len(p.query.split("&")) if p.query else 0, "query_keys": [key[:100] for key, _ in query], "encoded_characters": len(re.findall(r"%[a-fA-F0-9]{2}", url)),
            "url_entropy": entropy(url), "punycode": "xn--" in host}


def extract_keyword_features(url: str) -> dict:
    tokens = set(re.findall(r"[a-z]+", unquote(url).lower()))
    matched = sorted(tokens.intersection({"login", "signin", "verify", "secure", "account", "bank", "password", "payment", "billing", "wallet", "urgent", "suspended", "update", "confirm", "credential"}))
    return {"keyword_count": len(matched), "matched": matched, **{"has_" + k: k in tokens for k in ("login", "verify", "bank", "account", "secure", "update")}}


def extract_domain_features(url: str) -> dict:
    host = urlsplit(url).hostname
    parts = _SUFFIXES(host)
    return {"hostname": host, "registered_domain": registered_domain(host), "subdomains": parts.subdomain.split(".") if parts.subdomain else [],
            "domain_length": len(host), "num_subdomains": len(parts.subdomain.split(".")) if parts.subdomain else 0,
            "has_hyphen": "-" in host, "suspicious_tld": parts.suffix in {"tk", "cf", "ml", "ga", "gq", "top", "buzz", "icu", "click"}, "tld": parts.suffix}


def analyze_url_structure(url: str) -> dict:
    p = urlsplit(url)
    host = p.hostname
    parts = _SUFFIXES(host)
    return {"hyphen_count": host.count("-"), "subdomain_depth": len(parts.subdomain.split(".")) if parts.subdomain else 0,
            "entropy": entropy(parts.domain), "digit_ratio": round(sum(c.isdigit() for c in host) / max(1, len(host)), 3),
            "path_depth": len([s for s in p.path.split("/") if s]),
            "has_encoded_chars": bool(re.search(r"%(?:2f|3a|40|25)", url, re.I)), "has_double_extension": bool(re.search(r"\.(?:pdf|docx?|jpg|png)\.(?:exe|scr|js)$", p.path, re.I)),
            "embedded_url": bool(re.search(r"https?://", unquote(p.path + p.query), re.I))}


def is_shortened_url(url: str) -> dict:
    return {"is_shortened": urlsplit(url).hostname in {"bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "buff.ly", "is.gd", "t.co", "cutt.ly", "adf.ly"}}


def detect_brand_impersonation(url: str, title: str = "", has_credentials: bool = False) -> dict:
    host = urlsplit(url).hostname
    parts = _SUFFIXES(host)
    brand_tokens = re.findall(r"[a-z]+", (parts.subdomain + "." + parts.domain).lower())
    candidates = []
    for brand, official in LEGITIMATE_BRANDS.items():
        if any(host == d or host.endswith("." + d) for d in official):
            continue
        host_claim = brand in brand_tokens or parts.domain.startswith(brand + "-")
        title_claim = has_credentials and bool(re.search(r"\b" + re.escape(brand) + r"\b", title, re.I))
        if host_claim or title_claim:
            candidates.append({"brand": brand, "source": "hostname" if host_claim else "page title + credential form", "observed": host if host_claim else title[:200], "known_domains": official})
    # Candidate identity mismatch is an inference, never proof of impersonation.
    return {"is_impersonating": bool(candidates), "impersonated_brands": [c["brand"] for c in candidates], "brand_count": len(candidates), "candidates": candidates, "label": "Potential identity mismatch"}


def get_dns_record_count(url: str, target=None, deadline: float | None = None) -> dict:
    target = target or resolve_target(url, deadline)
    result = {"status": "completed", "hostname": target.hostname, "addresses": target.addresses,
              "records": {"A": [ip for ip in target.addresses if ":" not in ip], "AAAA": [ip for ip in target.addresses if ":" in ip]}, "errors": {}}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 0.8
    for kind in ("MX", "NS", "TXT"):
        remaining = min(0.8, deadline - time.monotonic()) if deadline else 0.8
        if remaining <= 0:
            result["errors"][kind] = "Scan time budget exhausted"
            continue
        try:
            result["records"][kind] = [str(item)[:500] for item in resolver.resolve(target.hostname, kind, lifetime=remaining, search=False)][:25]
        except dns.resolver.NoAnswer:
            result["records"][kind] = []
        except dns.exception.DNSException:
            result["errors"][kind] = "Lookup unavailable"
    result["dns_record_count"] = sum(len(values) for values in result["records"].values())
    if result["errors"]:
        result["status"] = "partial"
    return result


def check_spf_dmarc(url: str, dns_info: dict | None = None, deadline: float | None = None) -> dict:
    host = registered_domain(urlsplit(url).hostname)
    resolver = dns.resolver.Resolver()
    result = {"status": "completed", "spf_present": None, "dmarc_present": None, "domain": host}
    for name, query, prefix in (("spf_present", host, "v=spf1"), ("dmarc_present", "_dmarc." + host, "v=DMARC1")):
        remaining = min(0.8, deadline - time.monotonic()) if deadline else 0.8
        if remaining <= 0:
            result["status"] = "partial"
            continue
        try:
            if name == "spf_present" and dns_info and dns_info["hostname"] == host and "TXT" in dns_info["records"]:
                texts = dns_info["records"]["TXT"]
            else:
                texts = [str(r) for r in resolver.resolve(query, "TXT", lifetime=remaining, search=False)]
            result[name] = any(prefix.lower() in text.lower() for text in texts)
        except dns.resolver.NoAnswer:
            result[name] = False
        except dns.exception.DNSException:
            result["status"] = "partial"
    return result  # Missing mail records do not establish phishing.


def get_domain_age(url: str, deadline: float | None = None) -> dict:
    host = registered_domain(urlsplit(url).hostname)
    try:
        ipaddress.ip_address(host)
        return {"status": "not_applicable", "domain_age_days": None}
    except ValueError:
        pass
    source = "https://rdap.org/domain/" + host
    try:
        response = fetch_website(source, min(deadline or time.monotonic() + 3, time.monotonic() + 3), max_bytes=256 * 1024, max_redirects=3)
        import json
        if response["status_code"] != 200 or response["truncated"]:
            raise ValueError()
        record = json.loads(response["body"])
        events = record.get("events", [])
        for event in events:
            if event.get("eventAction") == "registration":
                created = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - created).days
                if age < 0:
                    raise ValueError()
                return {"status": "completed", "domain_age_days": age, "registered_at": created.isoformat(), "registered_domain": host, "source": response["final_url"]}
        return {"status": "unavailable", "domain_age_days": None, "reason": "Registration date not supplied by RDAP.", "source": source}
    except (ScanError, ValueError, TypeError, KeyError, AttributeError):
        return {"status": "unavailable", "domain_age_days": None, "reason": "RDAP registration information unavailable.", "source": source}


def get_certificate_info(url: str) -> dict:
    # Compatibility helper: full scan reuses the certificate from its existing connection.
    try:
        return fetch_website(url, time.monotonic() + 6, max_bytes=1)["tls"]
    except ScanError as exc:
        return {"status": "unavailable", "verified": None, "reason": str(exc)}


def destination(raw: str, base: str) -> dict:
    try:
        resolved = urljoin(base, raw.strip())
        p = urlsplit(resolved)
        base_host = urlsplit(base).hostname
        host = (p.hostname or "").lower()
        if len(host) > 253:
            raise ValueError("Invalid referenced hostname")
    except ValueError:
        return {"url": raw[:2000], "scheme": "invalid", "hostname": "", "external": False, "internal_literal": False}
    internal = host == "localhost" or host.endswith((".local", ".internal", ".localhost"))
    try:
        internal = internal or not public_ip(host)
    except ValueError:
        pass
    return {"url": resolved[:2000], "scheme": p.scheme, "hostname": host, "external": bool(host and not same_site(host, base_host)), "internal_literal": internal}


JS_PATTERNS = {
    "eval": r"\beval\s*\(", "encoded_payload": r"\batob\s*\(|(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u[0-9a-fA-F]{4}){8,}",
    "dynamic_code": r"\bnew\s+Function\s*\(", "document_write": r"\bdocument\.write\s*\(",
    "dynamic_navigation": r"(?:window\.)?location\.(?:href\s*=|replace\s*\(|assign\s*\()",
    "form_handling": r"\b(?:submit|onsubmit|FormData)\b", "network_send": r"\b(?:fetch|XMLHttpRequest|sendBeacon)\s*\("}


def inspect_javascript(text: str, source: str, base: str) -> dict:
    indicators = []
    for name, pattern in JS_PATTERNS.items():
        matches = list(re.finditer(pattern, text))
        if matches:
            indicators.append({"type": name, "count": len(matches), "samples": [text[max(0, m.start() - 30):m.end() + 60][:140] for m in matches[:2]]})
    destinations = sorted(set(re.findall(r"https?://[^\s'\"<>`\\)]+", text)))[:30]
    return {"source": source, "bytes_inspected": len(text.encode()), "indicators": indicators, "destinations": [destination(d, base) for d in destinations]}


def parse_content(response: dict, deadline: float | None = None) -> dict:
    base = response["final_url"]
    charset = re.search(r"charset=([\w-]+)", response["headers"].get("content-type", ""), re.I)
    try:
        text = response["body"].decode(charset.group(1) if charset else "utf-8", errors="replace")
    except LookupError:
        text = response["body"].decode("utf-8", errors="replace")
    soup = BeautifulSoup(text, "html.parser")
    initial_title = soup.title.get_text(" ", strip=True)[:300] if soup.title else ""
    blocked_title = bool(re.search(r"(?:your request has been blocked|access denied|request blocked|just a moment|attention required|verify you are human|security verification)", initial_title, re.I))
    if soup.base and soup.base.get("href"):
        # Malformed untrusted base URLs cannot turn a successful fetch into a 500.
        try:
            candidate = urljoin(base, soup.base["href"])
            urlsplit(candidate)
            base = candidate
        except ValueError:
            pass
    all_forms = soup.find_all("form")
    forms, resources, javascript, iframes = [], [], [], []
    all_inputs = soup.find_all("input")
    for i, form in enumerate(all_forms[:50]):
        inputs = form.find_all("input")
        password = sum(el.get("type", "text").lower() == "password" for el in inputs)
        payment = sum(bool(re.search(r"(?:cc-number|cc-csc|cc-exp|card.?number|card.?no|credit.?card|cvv|cvc)", " ".join(str(el.get(k, "")) for k in ("name", "id", "autocomplete")), re.I)) for el in inputs)
        actions = [destination(form.get("action", "") or response["final_url"], base)]
        actions.extend(destination(el["formaction"], base) for el in form.find_all(attrs={"formaction": True}))
        # Compare the actual page host, even if a remote <base> changes URL resolution.
        for action in actions:
            action["external"] = bool(action["hostname"] and not same_site(action["hostname"], urlsplit(response["final_url"]).hostname))
            action["cross_hostname"] = bool(action["hostname"] and action["hostname"] != urlsplit(response["final_url"]).hostname)
        forms.append({"id": f"form-{i + 1}", "method": str(form.get("method", "get")).lower(), "actions": actions[:20], "password_fields": password,
                      "payment_fields": payment, "input_types": dict(Counter(el.get("type", "text").lower() for el in inputs)),
                      "hidden_inputs": sum(el.get("type", "").lower() == "hidden" for el in inputs)})
    for i, frame in enumerate(soup.find_all("iframe")[:100]):
        style = re.sub(r"\s+", "", frame.get("style", "").lower())
        hidden = frame.has_attr("hidden") or "display:none" in style or "visibility:hidden" in style or str(frame.get("width")) == "0" or str(frame.get("height")) == "0"
        iframes.append({"id": f"iframe-{i+1}", **destination(frame.get("src", ""), base), "hidden": hidden})
    all_scripts = soup.find_all("script")
    for i, script in enumerate(all_scripts[:100]):
        if script.get("src"):
            resources.append({"id": f"script-{i+1}", "kind": "script", **destination(script["src"], base), "integrity": bool(script.get("integrity"))})
        elif script.get("type", "").lower() not in {"application/ld+json", "application/json"}:
            javascript.append(inspect_javascript(script.get_text()[:128 * 1024], f"inline-script-{i+1}", response["final_url"]))
    for i, tag in enumerate(soup.find_all(["link", "img", "video", "audio", "source", "embed", "object"])[:300]):
        value = tag.get("src") or tag.get("href") or tag.get("data")
        if value:
            resources.append({"id": f"resource-{i+1}", "kind": tag.name, **destination(value, base)})
    links = [destination(a["href"], base) for a in soup.find_all("a", href=True)[:500]]
    script_fetches = []
    script_deadline = min(deadline or time.monotonic() + 6, time.monotonic() + 6)
    fetched = set()
    for resource in ([] if blocked_title else [r for r in resources if r["kind"] == "script"][:2]):
        script_url = resource["url"]
        if script_url in fetched:
            continue
        fetched.add(script_url)
        if time.monotonic() >= script_deadline:
            script_fetches.append({"url": script_url, "status": "skipped", "reason": "Script time budget exhausted"})
            continue
        try:
            script_response = fetch_website(script_url, script_deadline, max_bytes=128 * 1024, max_redirects=2)
            if 200 <= script_response["status_code"] < 300:
                javascript.append(inspect_javascript(script_response["body"].decode("utf-8", errors="replace"), script_response["final_url"], response["final_url"]))
                script_fetches.append({"url": script_url, "final_url": script_response["final_url"], "status": "partial" if script_response["truncated"] else "completed", "bytes": script_response["bytes_received"]})
            else:
                script_fetches.append({"url": script_url, "status": "unavailable", "reason": f"HTTP {script_response['status_code']}"})
        except ScanError as exc:
            script_fetches.append({"url": script_url, "status": exc.code, "reason": str(exc)})
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    title = soup.title.get_text(" ", strip=True)[:300] if soup.title else ""
    visible_text = soup.get_text(" ", strip=True)[:4000]
    metas = [{"name": tag.get("name") or tag.get("property") or tag.get("http-equiv", ""), "content": str(tag.get("content", ""))[:500]} for tag in soup.find_all("meta")[:40]]
    refresh = [m for m in metas if m["name"].lower() == "refresh"]
    refresh_targets = []
    for meta in refresh:
        match = re.search(r"url\s*=\s*(.+)", meta["content"], re.I)
        if match:
            refresh_targets.append(destination(match.group(1).strip(" '\""), base))
    all_destinations = links + resources + iframes + [a for f in forms for a in f["actions"]] + refresh_targets + [d for js in javascript for d in js["destinations"]]
    external_domains = sorted({d["hostname"] for d in all_destinations if d["hostname"] and not same_site(d["hostname"], urlsplit(response["final_url"]).hostname)})
    tracker_patterns = {"google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager", "connect.facebook.net": "Meta SDK", "doubleclick.net": "DoubleClick"}
    trackers = [{"url": r["url"], "label": label} for r in resources for domain, label in tracker_patterns.items() if r["hostname"] == domain or r["hostname"].endswith("." + domain)]
    return {"status": "blocked_by_target" if blocked_title else "partial" if response["truncated"] else "completed", "title": title, "text_excerpt": visible_text,
            "num_forms": len(all_forms), "forms": forms, "password_fields": sum(el.get("type", "").lower() == "password" for el in all_inputs),
            "payment_fields": sum(f["payment_fields"] for f in forms), "hidden_inputs": sum(el.get("type", "").lower() == "hidden" for el in all_inputs),
            "iframes": iframes, "hidden_iframes": sum(f["hidden"] for f in iframes), "scripts_count": len(all_scripts), "resources": resources,
            "links": links, "external_links": sum(link["external"] for link in links), "external_domains": external_domains,
            "javascript": javascript, "script_fetches": script_fetches, "meta": metas, "meta_redirects": refresh_targets, "trackers": trackers,
            "sample_limits": {"forms": 50, "iframes": 100, "scripts": 100, "resources": 300, "links": 500, "external_scripts_downloaded": 2},
            "eval_count": sum(i["count"] for js in javascript for i in js["indicators"] if i["type"] == "eval")}


def extract_content_features(url: str) -> dict:
    try:
        return parse_content(fetch_website(url))
    except ScanError as exc:
        return {"status": "unavailable", "reason": str(exc)}


def extract_redirection_count(url: str) -> dict:
    try:
        response = fetch_website(url)
        return {"status": "completed", "redirection_count": len(response["redirect_chain"]), "chain": response["redirect_chain"], "final_url": response["final_url"], "final_domain": urlsplit(response["final_url"]).hostname}
    except ScanError as exc:
        return {"status": "unavailable", "reason": str(exc), "chain": getattr(exc, "redirect_chain", [])}


def analyze_url(url: str, on_event=None, deadline: float | None = None) -> dict:
    deadline = deadline or time.monotonic() + 38
    def event(stage, status="completed", detail=""):
        if on_event:
            on_event(stage, status, detail)
    url = normalize_url(url)
    event("URL validated", detail="HTTP/HTTPS on standard website ports; credentials and malformed hosts rejected")
    features = {"_original_url": url, "url": extract_url_features(url), "keywords": extract_keyword_features(url), "domain": extract_domain_features(url),
                "url_structure": analyze_url_structure(url), "shortener": is_shortened_url(url)}
    try:
        target = resolve_target(url, deadline)
    except ScanError as exc:
        if exc.code in {"blocked_destination", "invalid_url"}:
            raise
        target = None
        features["dns"] = {"status": "unavailable", "reason": str(exc), "addresses": []}
    if target:
        features["dns"] = get_dns_record_count(url, target, min(deadline, time.monotonic() + 2.5))
    event("DNS / host checked", features["dns"]["status"], ", ".join(features["dns"].get("addresses", [])) or features["dns"].get("reason", ""))
    features["email"] = check_spf_dmarc(url, features["dns"] if target else None, min(deadline, time.monotonic() + 1.6)) if target else {"status": "unavailable", "spf_present": None, "dmarc_present": None}
    response = None
    try:
        if not target:
            raise ScanError("Website could not be resolved.", "dns_error")
        response = fetch_website(url, min(deadline, time.monotonic() + 12), on_event=event, initial=target)
        http_status = response["status_code"]
        fetch_state = "blocked_by_target" if http_status in {401, 403, 407, 429, 451} else "http_error" if http_status >= 400 else "completed"
        features["http"] = {k: response[k] for k in ("status_code", "headers", "final_url", "connected_ip", "bytes_received", "truncated")}
        features["http"]["status"] = fetch_state
        features["certificate"] = response["tls"]
        features["redirection"] = {"status": "completed", "redirection_count": len(response["redirect_chain"]), "chain": response["redirect_chain"], "final_url": response["final_url"], "final_domain": urlsplit(response["final_url"]).hostname}
        event("Website fetched", "partial" if response["truncated"] else fetch_state, f"HTTP {http_status}; {response['bytes_received']} bytes; {response['final_url']}")
    except ScanError as exc:
        features["http"] = {"status": exc.code, "reason": str(exc), "final_url": None}
        features["certificate"] = {"status": "unavailable", "verified": None, "reason": str(exc)}
        chain = getattr(exc, "redirect_chain", [])
        features["redirection"] = {"status": "partial" if chain else "unavailable", "chain": chain, "redirection_count": len(chain), "reason": str(exc)}
        event("Website fetch", exc.code, str(exc))
    event("Redirects analyzed", features["redirection"]["status"], f"{len(features['redirection'].get('chain', []))} observed redirects")
    if response and features["http"]["status"] == "completed" and ("html" in response["headers"].get("content-type", "").lower()):
        features["content"] = parse_content(response, deadline)
        if features["content"]["status"] == "blocked_by_target":
            features["http"]["status"] = "blocked_by_target"
            features["http"]["reason"] = "Target returned a block / verification page rather than its normal content."
        event("HTML analyzed", features["content"]["status"], features["content"]["title"] or "No page title")
        event("Forms / scripts / resources inspected", features["content"]["status"], f"{features['content']['num_forms']} forms; {features['content']['scripts_count']} scripts; static inspection only")
    else:
        features["content"] = {"status": "unavailable", "reason": "Website fetch failed, target blocked the request, or response was not HTML."}
        event("HTML / scripts inspection", "skipped", features["content"]["reason"])
    features["security_headers"] = {name: features["http"].get("headers", {}).get(name) for name in ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy")}
    features["domain_age"] = get_domain_age(url, deadline) if target else {"status": "unavailable", "domain_age_days": None, "reason": "DNS unavailable"}
    observed_age = features["domain_age"].get("domain_age_days")
    event("Domain registration checked", features["domain_age"]["status"], str(observed_age) if observed_age is not None else features["domain_age"].get("reason", ""))
    content = features["content"]
    features["brand_impersonation"] = detect_brand_impersonation(features["http"].get("final_url") or url, content.get("title", ""), bool(content.get("password_fields") or content.get("payment_fields")))
    # Avoid sending URLs rejected for private DNS to third party services.
    if target:
        features["virus_total"] = check_url_virustotal(url, deadline)
        features["google_safe_browsing"] = check_google_safe_browsing(url, min(deadline, time.monotonic() + 5))
    else:
        features["virus_total"] = {"status": "skipped", "reason": "DNS validation unavailable"}
        features["google_safe_browsing"] = {"status": "skipped", "safe_browsing_flag": None}
    event("VirusTotal checked", features["virus_total"]["status"], f"{features['virus_total'].get('malicious', 'unavailable')} malicious detections")
    event("Safe Browsing checked", features["google_safe_browsing"]["status"], "Configured threat lookup" if features["google_safe_browsing"]["status"] == "completed" else "No completed lookup")
    return features


def calculate_risk_score(features: dict) -> int:
    from risk_engine import assess_risk
    return assess_risk(features)["score"]
