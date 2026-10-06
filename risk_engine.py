"""Explainable scoring. Points are heuristic weights, never probabilities."""
from __future__ import annotations
from urllib.parse import urlsplit

DIMENSIONS = {"url": ("URL manipulation", 25), "domain": ("Domain reputation", 15), "identity": ("Identity mismatch", 20),
              "credentials": ("Credential / payment collection", 40), "redirects": ("Redirect behavior", 15),
              "scripts": ("Script behavior", 15), "infrastructure": ("Infrastructure / transport", 20),
              "relationships": ("External relationships", 10), "intelligence": ("Threat intelligence", 85)}


def severity(score: int) -> str:
    return "CRITICAL" if score >= 85 else "HIGH" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LOW" if score >= 10 else "SAFE"


def assess_risk(features: dict) -> dict:
    evidence = []
    contributions = {k: 0 for k in DIMENSIONS}
    def finding(code, label, detail, source, category, weight=0, kind="observation"):
        remaining = DIMENSIONS[category][1] - contributions[category]
        points = min(max(0, weight), remaining)
        contributions[category] += points
        evidence.append({"id": code, "label": label, "detail": detail, "source": source, "dimension": category, "points": points, "kind": kind})

    url, structure, content = features.get("url", {}), features.get("url_structure", {}), features.get("content", {})
    finding("url.observed", "Submitted URL characteristics", {k: url.get(k) for k in ("hostname", "length", "path_depth", "query_count", "encoded_characters", "url_entropy")}, "Submitted URL", "url")
    if url.get("has_ip"):
        finding("url.ip", "IP address used as hostname", url["hostname"], "Submitted URL", "url", 5)
    if url.get("has_at"):
        finding("url.at", "@ character in URL path or query", "Embedded URL credentials are rejected before scanning.", "Submitted URL", "url", 2)
    if url.get("punycode"):
        finding("url.idn", "Internationalized hostname", url["hostname"], "Submitted URL", "url", 3)
    if structure.get("hyphen_count", 0) >= 3:
        finding("url.hyphens", "Multiple hostname hyphens", structure["hyphen_count"], "Parsed hostname", "url", 5)
    if structure.get("subdomain_depth", 0) >= 3:
        finding("url.subdomains", "Deep subdomain structure", structure["subdomain_depth"], "Offline public suffix parsing", "url", 5)
    if structure.get("entropy", 0) > 4 and structure.get("digit_ratio", 0) > 0.25:
        finding("url.randomness", "High entropy with digit-heavy hostname", {"entropy": structure["entropy"], "digit_ratio": structure["digit_ratio"]}, "Parsed hostname", "url", 4)
    if structure.get("has_encoded_chars") and structure.get("embedded_url"):
        finding("url.encoded", "Encoded nested URL", {"encoded": True, "embedded_url": True}, "Submitted path / query", "url", 4)
    if structure.get("has_double_extension"):
        finding("url.extension", "Executable path with double extension", features["_original_url"], "URL path", "url", 10)
    keywords = features.get("keywords", {}).get("matched", [])
    if keywords:
        finding("url.keywords", "Security / account keywords", keywords, "Tokenized URL; keywords alone do not establish phishing", "url", 3 if len(keywords) >= 3 else 0)
    if features.get("shortener", {}).get("is_shortened"):
        finding("url.shortener", "Known URL shortener", url.get("hostname"), "Shortener hostname list", "url", 3)
    if features.get("domain", {}).get("suspicious_tld"):
        finding("domain.tld", "TLD with historical abuse", features["domain"]["tld"], "Heuristic TLD list; does not establish maliciousness", "domain", 3)
    age = features.get("domain_age", {})
    if age.get("status") == "completed":
        finding("domain.age", "Observed registration age", {"days": age["domain_age_days"], "registered_at": age["registered_at"], "registered_domain": age.get("registered_domain") or features.get("domain", {}).get("registered_domain")}, age["source"], "domain", 10 if age["domain_age_days"] < 30 else 5 if age["domain_age_days"] < 90 else 0)
    dns = features.get("dns", {})
    if dns.get("addresses"):
        finding("dns.public", "Public DNS addresses validated", dns["addresses"], "DNS A / AAAA resolution before connection", "infrastructure")
    http = features.get("http", {})
    if http.get("status_code") is not None:
        finding("http.response", "HTTP response observed", {"status_code": http["status_code"], "final_url": http.get("final_url"), "bytes_received": http.get("bytes_received")}, "Pinned HTTP connection", "infrastructure")
    if http.get("status") == "blocked_by_target":
        finding("http.blocked", "Target blocked normal page inspection", {"status_code": http.get("status_code"), "title": content.get("title"), "reason": http.get("reason")}, "HTTP status or explicit block / verification page title", "infrastructure")
    cert = features.get("certificate", {})
    if cert.get("verified"):
        finding("tls.verified", "TLS certificate validated", {k: cert.get(k) for k in ("cert_issuer", "tls_version", "days_to_expiry")}, "TLS handshake on fetched destination", "infrastructure")
    elif http.get("status") == "tls_error":
        finding("tls.invalid", "TLS validation failed", http.get("reason"), "Verified TLS handshake failure; page content unavailable", "infrastructure", 8)
    final_url = http.get("final_url") or features["_original_url"]
    if urlsplit(final_url).scheme == "http":
        finding("tls.http", "Unencrypted HTTP URL", final_url, "Final URL" if http.get("final_url") else "Submitted URL", "infrastructure", 5)
    chain = features.get("redirection", {}).get("chain", [])
    if features.get("redirection", {}).get("status") == "completed" and not chain:
        finding("redirect.none", "No HTTP redirects observed", {"count": 0, "final_url": http.get("final_url")}, "Bounded HTTP fetch", "redirects")
    if chain:
        finding("redirect.observed", "HTTP redirect chain", chain, "HTTP Location headers", "redirects", 5 if len(chain) >= 3 else 0)
    if any(urlsplit(c["from"]).scheme == "https" and urlsplit(c["to"]).scheme == "http" for c in chain):
        finding("redirect.downgrade", "HTTPS to HTTP redirect", [c for c in chain if urlsplit(c["from"]).scheme == "https" and urlsplit(c["to"]).scheme == "http"], "HTTP Location headers", "redirects", 10)
    if http.get("status") == "blocked_destination" and chain:
        finding("redirect.internal", "Redirect to blocked destination", {"chain": chain, "reason": http.get("reason")}, "SSRF validation; blocked target not fetched", "redirects", 10)
    sensitive = bool(content.get("password_fields") or content.get("payment_fields"))
    if content.get("status") in {"completed", "partial"}:
        finding("html.observed", "HTML inspected", {"title": content.get("title"), "forms": content.get("num_forms"), "password_fields": content.get("password_fields"), "payment_fields": content.get("payment_fields"), "scripts": content.get("scripts_count"), "external_domains": content.get("external_domains")}, "Fetched HTML; bounded static inspection", "credentials")
        if content.get("text_excerpt"):
            finding("html.text", "Visible page text excerpt", content["text_excerpt"][:1600], "Fetched HTML text; untrusted website statements, not independently verified", "identity")
        for form in content.get("forms", []):
            form_sensitive = bool(form["password_fields"] or form["payment_fields"])
            if not form_sensitive:
                continue
            finding("form.observed." + form["id"], "Sensitive form structure observed", {"form": form["id"], "method": form["method"], "actions": form["actions"], "password_fields": form["password_fields"], "payment_fields": form["payment_fields"]}, "HTML form attributes; same-site hostname changes alone add no points", "credentials")
            external = [a["url"] for a in form["actions"] if a["external"]]
            insecure = [a["url"] for a in form["actions"] if a["scheme"] == "http"]
            invalid = [a["url"] for a in form["actions"] if a["scheme"] not in {"http", "https"} or a["internal_literal"]]
            if external:
                finding("form.external." + form["id"], "Sensitive form submits to another site", {"form": form["id"], "destinations": external, "password_fields": form["password_fields"], "payment_fields": form["payment_fields"]}, "HTML form action / formaction; private-aware public suffix site comparison", "credentials", 25, "risk_indicator")
            if insecure:
                finding("form.http." + form["id"], "Sensitive form submits over HTTP", {"form": form["id"], "destinations": insecure}, "HTML form action / formaction", "credentials", 25, "risk_indicator")
            if invalid:
                finding("form.invalid." + form["id"], "Sensitive form has an unusual destination", {"form": form["id"], "destinations": invalid}, "HTML form action / formaction; no form submission performed", "credentials", 15, "risk_indicator")
            if form["method"] == "get":
                finding("form.get." + form["id"], "Sensitive form uses GET", form["id"], "HTML form method; browser may place values in URL", "credentials", 10, "risk_indicator")
        if sensitive and urlsplit(final_url).scheme == "http":
            finding("form.page_http", "Credential collection on an unencrypted page", final_url, "Fetched URL + password/payment inputs", "infrastructure", 15, "risk_indicator")
        candidates = features.get("brand_impersonation", {}).get("candidates", [])
        if not candidates:
            finding("identity.checked", "No brand identity mismatch candidate detected", {"hostname": urlsplit(final_url).hostname, "title": content.get("title"), "candidates": []}, "Hostname/title comparison to curated domain list; incomplete identity coverage", "identity")
        for i, candidate in enumerate(candidates):
            finding("identity." + str(i), "Potential brand identity mismatch", candidate, candidate["source"] + "; curated domain list may be incomplete", "identity", 15 if sensitive else 5, "inference")
        for i, js in enumerate(content.get("javascript", [])):
            types = {indicator["type"] for indicator in js["indicators"]}
            if ("eval" in types or "dynamic_code" in types) and "encoded_payload" in types:
                finding("script.obfuscation." + str(i), "Encoded payload with dynamic execution pattern", js, "Static JavaScript source; code was not executed", "scripts", 10, "risk_indicator")
            if sensitive and {"form_handling", "network_send", "encoded_payload"}.issubset(types):
                finding("script.form." + str(i), "Encoded script handles forms and network sends", js, "Static JavaScript source; combination is heuristic", "scripts", 5, "risk_indicator")
        finding("scripts.coverage", "Static script inspection coverage", {"scripts_in_html": content.get("scripts_count"), "sources_inspected": [js["source"] for js in content.get("javascript", [])], "external_fetches": content.get("script_fetches", []), "download_limit": 2}, "Inline sources and bounded external script downloads; never executed", "scripts")
        finding("relationships.observed", "External domains referenced by the page", content.get("external_domains", []), "HTML attributes and static script URL strings; references are not proof of compromise", "relationships")
        hidden_external = [frame for frame in content.get("iframes", []) if frame["hidden"] and frame["external"]]
        if sensitive and hidden_external:
            finding("relationships.iframe", "Hidden external frames alongside sensitive inputs", hidden_external, "Fetched iframe attributes + form inputs; trackers can use hidden frames", "relationships", 5, "risk_indicator")
        finding("headers.observed", "Security headers", features.get("security_headers", {}), "HTTP response headers; absence alone is not phishing", "infrastructure")
    vt = features.get("virus_total", {})
    if vt.get("status") in {"completed", "in-progress"} and vt.get("total"):
        malicious, suspicious = vt.get("malicious", 0), vt.get("suspicious", 0)
        finding("intel.virustotal", "VirusTotal vendor results", {k: vt.get(k) for k in ("status", "malicious", "suspicious", "harmless", "undetected", "total", "vendors", "analysis_date")}, "VirusTotal API v3 " + vt.get("source", ""), "intelligence", 85 if malicious >= 3 else 65 if malicious >= 2 else 45 if malicious == 1 else 20 if suspicious else 0, "vendor_assessment")
    gsb = features.get("google_safe_browsing", {})
    if gsb.get("status") == "completed":
        finding("intel.safebrowsing", "Google Safe Browsing lookup", gsb.get("matches", []), "Google Safe Browsing v4", "intelligence", 85 if gsb.get("safe_browsing_flag") == 0 else 0, "vendor_assessment")
    score = min(100, sum(contributions.values()))
    unavailable = []
    for name, value in (("Website fetch", http), ("HTML", content), ("TLS", cert), ("Domain age", age), ("DNS", dns), ("VirusTotal", vt), ("Safe Browsing", gsb)):
        if value.get("status") not in {"completed", "not_applicable"}:
            unavailable.append({"source": name, "status": value.get("status", "unavailable"), "reason": value.get("reason") or value.get("error") or "Incomplete or not configured"})
    if any(fetch.get("status") != "completed" for fetch in content.get("script_fetches", [])):
        unavailable.append({"source": "External script inspection", "status": "partial", "reason": "Some selected script downloads were unavailable or truncated; inspect the script coverage evidence."})
    content_available = content.get("status") in {"completed", "partial"}
    known_threat = bool(vt.get("malicious", 0) or (gsb.get("status") == "completed" and gsb.get("safe_browsing_flag") == 0))
    if not content_available:
        state = http.get("status") if http.get("status") not in {"completed", None} else "partial"
    elif content.get("status") == "partial" or unavailable:
        state = "partial"
    else:
        state = "completed"
    # Low observed risk with missing HTML is not a safety verdict.
    assessment = severity(score) if content_available or known_threat or score >= 30 else "UNKNOWN"
    recommendation = "Do not submit credentials or payment details; verify the destination independently." if score >= 30 else "Analysis is incomplete; verify the website independently before sharing sensitive information." if not content_available else "No strong threat evidence was observed. Verify the hostname and context before sharing sensitive information."
    dna = []
    for key, (label, cap) in DIMENSIONS.items():
        ids = [e["id"] for e in evidence if e["dimension"] == key]
        available = bool(ids) if key not in {"credentials", "scripts", "relationships", "identity"} else content_available
        dna.append({"key": key, "label": label, "points": contributions[key] if available else None, "cap": cap, "evidence_ids": ids, "available": available})
    return {"score": score, "severity": severity(score), "assessment": assessment, "state": state, "recommendation": recommendation,
            "evidence": evidence, "unavailable": unavailable, "dna": dna, "policy": "phish-x-evidence-v1", "score_note": "Heuristic evidence points (0–100), not a probability or guarantee of safety."}


def attack_surface(features: dict) -> dict:
    content = features.get("content", {})
    available = content.get("status") in {"completed", "partial"}
    destinations = [a for form in content.get("forms", []) for a in form["actions"] if (form["password_fields"] or form["payment_fields"]) and (a["external"] or a["scheme"] != "https" or a["internal_literal"])]
    return {"available": available, "forms": content.get("num_forms"), "password_fields": content.get("password_fields"), "payment_fields": content.get("payment_fields"),
            "scripts": content.get("scripts_count"), "iframes": len(content["iframes"]) if available else None, "hidden_inputs": content.get("hidden_inputs"),
            "external_domains": content.get("external_domains", []) if available else None, "resources": len(content["resources"]) if available else None,
            "redirects": len(features.get("redirection", {}).get("chain", [])), "suspicious_destinations": destinations if available else None,
            "security_headers": features.get("security_headers", {}), "trackers": content.get("trackers", []) if available else None,
            "note": "Static snapshot of the fetched response. Lists are bounded; no JavaScript execution, login or form submission."}


def relationship_graph(features: dict, risk: dict) -> dict:
    nodes, edges, lookup = [], [], {}
    def node(kind, label, value):
        key = (kind, value)
        if key not in lookup:
            identifier = "n" + str(len(nodes))
            lookup[key] = identifier
            nodes.append({"id": identifier, "kind": kind, "label": label[:160], "value": value})
        return lookup[key]
    def edge(a, b, label):
        if a != b and not any(e["from"] == a and e["to"] == b and e["label"] == label for e in edges):
            edges.append({"from": a, "to": b, "label": label})
    submitted = features["_original_url"]
    root = node("url", "Submitted: " + submitted, submitted)
    parent = root
    for hop in features.get("redirection", {}).get("chain", []):
        child = node("url", hop["to"], hop["to"])
        edge(parent, child, "HTTP " + str(hop["status_code"]))
        parent = child
    final = features.get("http", {}).get("final_url")
    if final:
        final_node = node("url", "Fetched: " + final, final)
        edge(parent, final_node, "fetched")
        parent = final_node
    content = features.get("content", {})
    for form in content.get("forms", [])[:12]:
        child = node("form", form["id"] + f" ({form['password_fields']} password fields)", form["id"])
        edge(parent, child, "contains")
        for action in form["actions"][:3]:
            action_node = node("destination", action["url"], action["url"])
            edge(child, action_node, form["method"].upper() + " action")
    for resource in content.get("resources", [])[:18]:
        child = node("resource", resource["kind"] + ": " + resource["url"], resource["url"])
        edge(parent, child, "references")
        if resource["hostname"]:
            domain_node = node("domain", resource["hostname"], resource["hostname"])
            edge(child, domain_node, "hosted on")
    for frame in content.get("iframes", [])[:4]:
        child = node("iframe", frame["url"], frame["url"])
        edge(parent, child, "embeds")
    for hostname in content.get("external_domains", [])[:18]:
        child = node("domain", hostname, hostname)
        edge(parent, child, "observed external relationship")
    for finding in [e for e in risk["evidence"] if e["points"] > 0][:15]:
        child = node("indicator", finding["label"], finding["id"])
        edge(parent if final else root, child, "evidence " + finding["id"])
    return {"nodes": nodes, "edges": edges, "bounded": True, "note": "Observed URLs and source references; referenced resources were not all crawled."}
