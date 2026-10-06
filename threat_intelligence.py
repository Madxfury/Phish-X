"""Optional server-side intelligence with explicit availability and bounded API calls."""
from __future__ import annotations

import base64
from collections import deque
import json
import os
import re
import threading
import time

import requests

_vt_lock = threading.Lock()
_vt_requests = deque()
_vt_cooldown = 0.0
_shared_vt_quota = None


def set_shared_vt_quota(guard):
    global _shared_vt_quota
    _shared_vt_quota = guard


def configured_key(name: str) -> str:
    value = os.getenv(name, "").strip()
    return "" if not value or value.startswith(("your_", "replace_")) else value


def api_json(method: str, endpoint: str, deadline: float, read_timeout: float = 4, **kwargs):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise requests.Timeout("Service time budget exhausted")
    with requests.Session() as session:
        session.trust_env = False
        with session.request(method, endpoint, timeout=(min(2, remaining), min(read_timeout, remaining)), allow_redirects=False, stream=True, **kwargs) as response:
            body = bytearray()
            for chunk in response.iter_content(32768):
                body.extend(chunk)
                if len(body) > 2 * 1024 * 1024 or time.monotonic() >= deadline:
                    raise requests.Timeout("Service response exceeded limits")
            try:
                data = json.loads(body)
            except (ValueError, UnicodeError):
                data = None
            return response.status_code, dict(response.headers), data


def _vt_request(method: str, path: str, deadline: float, key: str, **kwargs):
    global _vt_cooldown
    with _vt_lock:
        now = time.monotonic()
        while _vt_requests and _vt_requests[0] < now - 60:
            _vt_requests.popleft()
        if now < _vt_cooldown or len(_vt_requests) >= int(os.getenv("VT_REQUESTS_PER_MINUTE", "4")):
            return 429, {"Retry-After": str(max(1, int(_vt_cooldown - now), 60 - int(now - _vt_requests[0]) if _vt_requests else 1))}, None
        _vt_requests.append(now)
    if _shared_vt_quota and not _shared_vt_quota(int(os.getenv("VT_REQUESTS_PER_MINUTE", "4"))):
        return 429, {"Retry-After": "60"}, None
    status, headers, data = api_json(method, "https://www.virustotal.com/api/v3/" + path, deadline, headers={"x-apikey": key, "Accept": "application/json"}, **kwargs)
    if status == 429:
        with _vt_lock:
            retry = headers.get("Retry-After", headers.get("retry-after", "60"))
            _vt_cooldown = time.monotonic() + (min(3600, int(retry)) if str(retry).isdigit() else 60)
    return status, headers, data


def _vt_error(status: int, headers: dict) -> dict:
    names = {429: "rate_limited", 401: "unauthorized", 403: "unauthorized", 404: "unavailable"}
    return {"status": names.get(status, "error"), "error": f"VirusTotal returned HTTP {status}.", "retry_after": headers.get("Retry-After", headers.get("retry-after"))}


def _vt_stats(attributes: dict, report: bool) -> dict:
    stats = attributes.get("last_analysis_stats" if report else "stats")
    if not isinstance(stats, dict) or not stats or any(type(n) is not int or n < 0 for n in stats.values()):
        raise ValueError("Missing or malformed VirusTotal statistics")
    detections = attributes.get("last_analysis_results" if report else "results", {})
    if not isinstance(detections, dict):
        raise ValueError("Malformed vendor results")
    vendors = [{"vendor": str(name)[:100], "category": item.get("category"), "result": str(item.get("result") or "")[:300]}
               for name, item in detections.items() if isinstance(item, dict) and item.get("category") in {"malicious", "suspicious"}][:50]
    return {**{k: stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")}, "stats": stats,
            "total": sum(stats.values()), "vendors": vendors, "analysis_date": attributes.get("last_analysis_date" if report else "date")}


def check_url_virustotal(url: str, deadline: float | None = None) -> dict:
    key = configured_key("VIRUSTOTAL_API_KEY")
    if not key:
        return {"status": "not_configured", "error": "VirusTotal API key is not configured."}
    deadline = min(deadline or time.monotonic() + 9, time.monotonic() + 9)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        status, headers, data = _vt_request("GET", "urls/" + url_id, deadline, key)
        if status == 200:
            attributes = data["data"]["attributes"]
            stats = _vt_stats(attributes, True)
            return {"status": "completed", "source": "existing_report", "url": url, **stats}
        if status != 404:
            return _vt_error(status, headers)
        status, headers, data = _vt_request("POST", "urls", deadline, key, data={"url": url})
        if status not in {200, 201}:
            return _vt_error(status, headers)
        analysis_id = data["data"]["id"]
        if not isinstance(analysis_id, str) or not re.fullmatch(r"[A-Za-z0-9_+=-]{1,512}", analysis_id):
            raise ValueError("Invalid analysis ID")
        result = {"status": "queued", "source": "submitted_analysis", "analysis_id": analysis_id, "url": url}
        # Poll the analysis resource, not the URL report. Stop at the request/time budget.
        for attempt in range(2):
            if deadline - time.monotonic() < 0.5:
                break
            if attempt:
                delay = min(1.0 * (2 ** attempt), max(0, deadline - time.monotonic() - 0.5))
                if delay:
                    time.sleep(delay)
            status, headers, data = _vt_request("GET", "analyses/" + analysis_id, deadline, key)
            if status != 200:
                return {**_vt_error(status, headers), "analysis_id": analysis_id}
            attributes = data["data"]["attributes"]
            state = attributes.get("status")
            if state not in {"queued", "in-progress", "completed"}:
                raise ValueError("Invalid analysis status")
            result["status"] = state
            if state in {"in-progress", "completed"} and attributes.get("stats"):
                result.update(_vt_stats(attributes, False))
            if state == "completed":
                if "total" not in result:
                    raise ValueError("Completed analysis has no statistics")
                break
        return result
    except requests.RequestException:
        return {"status": "unavailable", "error": "VirusTotal network request failed or timed out."}
    except (KeyError, ValueError, TypeError, AttributeError):
        return {"status": "error", "error": "VirusTotal returned a malformed report."}


def check_google_safe_browsing(url: str, deadline: float | None = None) -> dict:
    key = configured_key("SAFE_BROWSING_API_KEY")
    if not key:
        return {"status": "not_configured", "safe_browsing_flag": None}
    payload = {"client": {"clientId": "phish-x-ai", "clientVersion": "3.0"}, "threatInfo": {
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    try:
        status, _, data = api_json("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find", deadline or time.monotonic() + 5, params={"key": key}, json=payload)
        if status != 200 or not isinstance(data, dict) or not isinstance(data.get("matches", []), list):
            return {"status": "error", "safe_browsing_flag": None, "error": "Safe Browsing response unavailable or malformed."}
        matches = [{"threat_type": m.get("threatType"), "platform": m.get("platformType"), "url": m.get("threat", {}).get("url")} for m in data.get("matches", []) if isinstance(m, dict)]
        return {"status": "completed", "safe_browsing_flag": 0 if matches else 1, "matches": matches}
    except (requests.RequestException, ValueError, AttributeError):
        return {"status": "unavailable", "safe_browsing_flag": None, "error": "Safe Browsing network request failed."}
