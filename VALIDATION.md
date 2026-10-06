# Phish-X AI release validation

Validated on 6 October 2026 against the directly modified existing project. Flask/Jinja, all six original pages, the stylesheet and original branding remain. Localhost runs on port 5057. These are measured tests, not guaranteed future website/service behavior.

## Automated checks

**83 offline regression tests passed** with Python 3.12.13. Fixtures use temporary databases and cannot consume configured service keys or seed production history. Coverage includes SSRF/DNS pinning, redirects/compression limits, malformed HTML/Origin, client verdict spoofing, scoring sources, cache completeness, visitor/report ownership, actual-provider response validation, bounded Retry-After behavior, file-worker limits, database fallback, enforced Postgres certificate/hostname verification and production configuration gates. SocketIO tests confirm only the submitting visitor receives its actual scan stages.

Python compilation and **12 rendered JavaScript sections/files** parsed successfully. **14 source/CDN assets match** after asset preparation; all **five original PNG assets are byte-for-byte unchanged**. The fresh Python 3.12 environment passed pip check. A fresh pip-audit inspected 90 installed packages and found no known advisories; this does not rule out undisclosed vulnerabilities. All 67 runtime dependency wheels resolved for CPython 3.12 Linux x86_64, with approximately 146.2 MiB unpacked contents. Runtime dependencies are resolved in requirements-lock.txt. This is a dependency compatibility/size check, not an actual Vercel build or execution test.

## Real websites and AI

| Target | Actual observation | AI / intelligence |
| --- | --- | --- |
| Google | HTTP 200, parsed HTML, DNS/TLS/RDAP; SAFE, score 0 | Real Groq explanation and completed VirusTotal URL report |
| GitHub | HTTP 200, parsed HTML/resources; SAFE, score 0 | Real Groq explanation and completed VirusTotal URL report |
| Microsoft | HTTP 200 returned a verification/block page; normal content unavailable; UNKNOWN, score 0 | Real Groq UNKNOWN explanation; no invented page-content findings |
| AMTSO test page | Actual fetched page; CRITICAL, score 85 from vendor classifications | Real Groq explanation verified; a later transient 429 was displayed honestly, and reasoning over the same verified evidence subsequently completed |
| Harmless controlled httpbin-to-example.com redirect | Actual HTTPS-to-HTTP redirect and encoded URL/account tokens; LOW, score 22 | Real Groq LOW explanation; amber shield rendered; unavailable intelligence remained explicit |

AMTSO is an intentionally recognizable, harmless security test. Vendor classifications do not prove malicious intent/activity. See [AMTSO test information](https://www.amtso.org/feature-settings-check-phishing-page/).

The latest recorded full flow reported zero malicious/suspicious Google detections across 92 VirusTotal engines, and 12 malicious classifications across 92 engines for AMTSO. Vendor counts/dates are returned observations and can change. Missing/failed lookups never fabricate zero detections.

Groq uses openai/gpt-oss-120b with strict JSON schema and citation IDs limited to actual collected evidence. An invented citation on Microsoft's verification page was discarded; constraining allowed IDs corrected the failure and a real UNKNOWN assessment completed. Visible page text now has a citable source. AI interpretations can be wrong; confidence is self-reported rather than calibrated. One short provider-requested Retry-After can be retried within the scan deadline; longer failures remain explicit.

The earlier OpenAI request returned exhausted credit. Groq is now selected; no successful OpenAI result is claimed. Ollama and Safe Browsing have not been live-tested. All optional service failures preserve deterministic analysis.

## Complete localhost flow

All original pages and capabilities returned successfully. Real single scans ran through fetch, evidence extraction, risk, AI, storage and returned timeline. Google/GitHub bulk scans used the same pipeline. Crawler seed submission returned the same verified cached scan ID. PDF report download used the completed Google ID without increasing history or performing a second scan.

Controlled PDF and benign official Androguard TestActivity.apk uploads returned actual static observations. APK identity was tests.androguard, SDK 9/16, version code 1/name 1.0, zero requested permissions. The APK was not executed or distributed. Uploads remain bounded temporary workers, with time/CPU and Linux memory limits.

Empty/FTP input returned 400; loopback returned 403. Malformed Origin and oversized requests reject before provider work. A separate visitor received empty history, 404 for another visitor's evidence and 409 for its report; guessed URLs/IDs do not expose another visitor's cached scan.

Earlier actual network tests observed public redirects, a blocked redirect toward metadata, a slow-target timeout, unavailable-host DNS failure and HTTP 403. Failed fetches never claimed normal HTML analysis. Offline tests additionally cover private/mixed/transition IPs, unsupported ports/protocols, redirect limits and rebinding-resistant connections.

## Browser and UI

Green safe, red harmful and amber warning shields all rendered against genuine scans. UNKNOWN/errors use a neutral icon. Wide results fill available desktop content space; original controls/sidebar/background/logo remain. The graph shows selected real incoming/outgoing relationships without crossing-line clutter. Timeline stages retain measured status/time/detail; their red left rails are removed.

At 1366 x 900 and 390 x 844, stable pages had no horizontal overflow. At 390 pixels, scanner/bulk/result areas measured 326 pixels wide; +/- frames were 36 x 44 with smaller circular visuals and tight spacing. Adding/removing rows preserved entered URLs. Dashboard navigation, return and reload retained the exact GitHub timestamp, URL and bulk input, with no intro overlay and closed mobile navigation. First-visit terminal/decryption remain; restored browser state never becomes backend-authoritative evidence.

Contact uses plain-link styling and the supplied portfolio. Email uses a Gmail compose/sign-in continuation with the supplied recipient. Signed-out testing reached Google sign-in; authenticated composition was not tested and no email was sent.

## Report layout

The sample uses actual stored Google evidence and a real Groq explanation. All pages were rendered and inspected for clipping and missing glyphs. Typographic dashes are normalized; unsupported website characters remain visible as Unicode escapes. Tables, logo and page footers are readable. A regression checks preservation of those exported values.

## Vercel and remaining external work

Local tests verify HTTP-only Vercel mode, no SocketIO, two-URL bulk limits, 4 MiB uploads, explicit linked-crawl rejection and missing-database/secret gates. The 48-second analysis budget reserves time for persistence under the configured 60-second limit. Application budgets do not guarantee cloud timing.

Neon Postgres is the preferred durable backend, with full JSONB evidence, visitor ownership, indexed summaries, retention and atomic shared counters. MongoDB remains an alternative; local SQLite stores real data. /api/readiness checks an actual database connection and required configuration.

**Real Neon pooled storage passed live checks:** certificate-verified connection, full GitHub scan JSONB persistence, matching retrieval from a fresh ScanStore with an empty local database, separate-visitor denial, atomic true/true/false shared-counter behavior and a four-page PDF regenerated from the same stored scan. Groq and VirusTotal completed for that scan. A startup parameter incompatibility was fixed using transaction-local two-second statement and one-second lock timeouts; their effective values were verified against Neon. Actual Vercel build/runtime, cold starts, cloud egress and file workers still require verification.

Follow README's concrete Neon setup and cloud verification steps before shipping. /tmp SQLite is only an emergency instance mirror; new production work stops when durable configuration is missing. The ZIP excludes environment files/credentials, local databases, uploads/fixtures, caches, generated CDN copies and virtual environments. Archive contents and configured secret strings are checked before delivery.

## Fresh diagnostic follow-up

A new HTTP session verified every page, Google/GitHub HTML and Groq reasoning, Microsoft target-block handling, all four VirusTotal reports, harmless AMTSO warning, cached bulk results, a three-page PDF using the same scan ID, APK/PDF upload observations and cross-visitor history/report isolation. The live linked crawler fetched all three controlled httpbin pages (seed plus two links). Groq/VT rate limits and one invalid model response were represented as unavailable coverage; no replacement AI output was fabricated.

The old running process could not write SQLite under its original sandbox permissions. Restarting with the project's granted write access restored actual persistence. A storage failure now also returns completed scan evidence with an explicit unsaved-history limitation. Connection retries use at most four already-vetted public IPs within a single TCP budget, preserving IP pinning and original TLS hostname verification. Crawler/history/upload requests now time out and reset their UI controls.

A fresh browser scan completed real GitHub fetch, VirusTotal and Groq explanation. Dashboard navigation and reload preserved its exact timestamp and input, with no horizontal overflow. A dedicated free Neon database named phish-x-ai was created and Vercel shows it as Available and connected only to phish-x Preview/Production. The connection is now privately configured and live cloud persistence is verified. No credentials are included in release files.

## Live Neon serverless-mode follow-up

With VERCEL=1, an HTTPS Flask client, real Neon credentials and a fresh instance-local mirror, /api/readiness returned 200 with no issues. Real Google single scanning and Google/GitHub bulk scanning completed website fetching, Groq reasoning and VirusTotal reports, with durable Postgres results. A stored-evidence three-page report downloaded, a separate visitor received empty history/404 evidence, linked crawling returned the documented serverless_limit, and an oversized upload returned 413. Controlled PDF and benign APK processing returned the measured observations above. This verifies the serverless application path locally; actual Vercel runtime remains a separate check.
