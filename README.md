# Phish-X AI

**AI-powered phishing and website threat analysis** built on the existing Phish-X Flask/Jinja application. The original dark UI, sidebar, animations, PNG assets and six pages remain the foundation.

Phish-X AI combines live website inspection, security signals, optional threat intelligence and an optional, genuine language-model reasoning stage. It explains the evidence behind an assessment. A score is an explainable heuristic, not a probability, malware proof or guarantee of safety.

## Run on localhost

Use Python 3.12. The release was tested with Python 3.12.13; `.python-version` selects 3.12 for Vercel. Runtime dependencies are pinned in both `requirements.txt` and `requirements-lock.txt`. The deploy file is flat because Vercel's requirements parser rejects an included constraints file. From this project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env  # only when you do not already have .env
# Configure .env, then:
python app.py
```

The default address is `http://127.0.0.1:5001`. Set `FLASK_PORT` to an unused port if necessary. The directly modified development copy uses port **5057**. `FLASK_DEBUG=False` and `FLASK_HOST=127.0.0.1` are the defaults. The Flask development server is for localhost; use a suitable WSGI deployment for public use.

Open Home, enter a public HTTP/HTTPS URL, and select **Scan URL**. Results include the observed score, assessment, coverage state, evidence, DNA, attack surface, relationship graph, timeline and AI availability. **Rescan live** bypasses the five-minute cache. **View Recent Scans** restores the complete stored record. The PDF download uses that record and does not scan again.

## Configure real AI reasoning

AI is optional to the deterministic scanner but required for an actual AI assessment. There is no simulated fallback. The selected and successfully live-tested provider is Groq:

```dotenv
AI_PROVIDER=groq
GROQ_API_KEY=your_server_side_key
GROQ_MODEL=openai/gpt-oss-120b
```

Groq uses its server-side Chat Completions API with strict JSON schema output. The model receives collected evidence, with permitted citation IDs constrained to those actual observations. See [Groq structured outputs](https://console.groq.com/docs/structured-outputs). No Groq SDK or frontend credential is required.

OpenAI remains supported as an alternative:

```dotenv
AI_PROVIDER=openai
OPENAI_API_KEY=your_server_side_key
OPENAI_MODEL=gpt-4.1-mini
```

The OpenAI integration calls the Responses API with structured JSON output, no tools, and `store=false`. Use a model with Responses API structured-output support. See the [official structured outputs documentation](https://developers.openai.com/api/docs/guides/structured-outputs).

Alternatively, run your own Ollama service with a downloaded model that supports structured output, and set:

```dotenv
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=the_model_you_have_installed
```

`AI_PROVIDER=auto` selects Groq, then OpenAI, then a configured Ollama model. `none` disables AI. Restart Flask after configuration changes. Ollama on your laptop is not reachable at `127.0.0.1` from a Vercel function; use Groq, OpenAI or an appropriately secured, reachable service there.

The model receives measured evidence IDs, observations, limited page text and unavailable-source records. Website text is explicitly untrusted data, not instructions. The server validates the response schema, evidence references, confidence range, unsupported numeric/URL claims and safety claims against coverage. It attaches the exact supporting observations. Model interpretations can still be wrong; validation cannot prove every natural-language inference. AI cannot overwrite the deterministic score or downgrade its warning. Invalid outputs are discarded. Groq permits one short retry when its actual Retry-After header and remaining deadline allow it; longer rate limits are returned explicitly. Confidence is the model's self-reported judgment, not a calibrated probability.

**Validation status:** Actual Groq assessments completed for measured Google, GitHub, Microsoft verification-page and AMTSO test-page evidence. The earlier OpenAI request returned exhausted credit; it is not the selected provider. AI network errors, rate limits, malformed responses, invented citation IDs and unsupported facts remain explicit failure states. Ollama has not been live-tested.

## Server-side services and secrets

| Variable | Purpose |
| --- | --- |
| `VIRUSTOTAL_API_KEY` | Real VirusTotal v3 URL reports, submission and bounded analysis-status polling |
| `VT_REQUESTS_PER_MINUTE` | Outbound cap; default 4/minute, shared through the database on Vercel, subject to actual account quotas |
| `SAFE_BROWSING_API_KEY` | Optional Google Safe Browsing v4 lookup |
| `DATABASE_URL` | Recommended pooled Neon Postgres connection; `POSTGRES_URL` is also accepted |
| `MONGODB_URI` | Alternative durable backend; `MONGO_URI` also works; Postgres takes precedence |
| `MONGODB_DATABASE` | Mongo database name; default `phishing_detection` |
| `SECRET_KEY` | Stable random server secret; at least 32 characters required on Vercel; use 64 random hex characters |
| `FLASK_DEBUG`, `FLASK_HOST`, `FLASK_PORT` | Local server configuration |
| `AI_PROVIDER`, `GROQ_API_KEY`, `GROQ_MODEL` | Selected Groq configuration |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | Optional OpenAI configuration |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | Administrator-configured Ollama endpoint and model |
| `LOCAL_DB_PATH` | Optional SQLite path; blank uses the default |
| `SCAN_CACHE_TTL` | Cache lifetime in seconds; default 300 |
| `SCAN_REQUESTS_PER_MINUTE` | Per-IP scan/upload cap; default 12/minute; shared database counter on Vercel |
| `LOG_LEVEL` | Logging level; default INFO |

Only put actual secrets in server environment variables or ignored `.env`. `.env.example` and the distribution ZIP contain no real keys. The supplied service credentials are configured only in the directly modified local project's ignored `.env`; configure credentials separately after extracting the ZIP or deploying. Operating-system environment variables take precedence, then `.env.local`, then `.env`. Both local environment files are excluded from deployment and the ZIP. No API credential is rendered into HTML, frontend JavaScript or browser API requests.

VirusTotal first looks for an existing report. A missing report is submitted, then its analysis resource is polled within a nine-second/request budget. Queued/in-progress, unauthorized, malformed, rate-limited and network-error states remain distinct. No completed counts are invented. Vendor results and their analysis timestamp are shown; they are third-party assessments and can be stale or wrong. [VirusTotal analysis states](https://docs.virustotal.com/reference/analyses-object).

## What the scanner actually inspects

1. Normalize and validate the submitted URL; reject unsupported schemes, embedded credentials and malformed hosts.
2. Resolve and validate all A/AAAA addresses; collect bounded DNS and optional mail-policy observations.
3. Fetch the website using a pinned public IP, verified TLS, bounded redirects and a bounded response body.
4. Parse fetched HTML: title, text, metadata, forms, `action`/`formaction`, input types, password/payment fields, hidden inputs, frames, links and resources.
5. Inspect inline JavaScript and at most two downloaded script files statically. Record combinations of encoded/dynamic code, form/network handling and navigation indicators. Do not execute scripts or submit forms.
6. Look up domain registration through RDAP where available; check configured threat-intelligence services.
7. Calculate explainable evidence points, build DNA/snapshot/graph, and optionally ask the configured AI provider to interpret the evidence.
8. Save the complete scan and return actual stage statuses.

Form destinations use a private-suffix-aware site comparison, so separate GitHub Pages/Vercel tenants are not treated as one trusted site. Cross-hostname changes within one site are retained as observations. Registration age describes the named registrable domain, which may be a hosting provider rather than the individual tenant.

The page body is limited to **1 MiB**; downloaded scripts to **128 KiB each**. HTTP redirects are limited to five; script redirects to two. There are bounded connection/read deadlines and a 48-second analysis budget, leaving room for persistence within the 60-second function limit, with up to 14 seconds reserved for AI. Website fetching has a 12-second sub-budget. These are bounded best-effort budgets, not a background job system.

HTML lists are sampled: 50 forms, 100 frames, 100 script elements, 300 non-script resource elements and 500 links. Counts and bounded lists are identified in the UI. Payment-field classification is based on sampled form attributes. Detection does not see content generated only after JavaScript execution, authenticated pages, all external scripts, visual brand copying or every tracker. The graph contains observed entities and references, not proof that a referenced domain is compromised.

## Risk, DNA and scan states

| Score | Severity |
| --- | --- |
| 0–9 | SAFE |
| 10–29 | LOW |
| 30–59 | SUSPICIOUS |
| 60–84 | HIGH |
| 85–100 | CRITICAL |

Every weighted finding retains its source, evidence ID, observed detail and awarded points. Category caps prevent repetitive features from accumulating unlimited risk. Key examples: external sensitive form submissions 25 points; sensitive submissions over HTTP 25; encoded JavaScript plus dynamic execution 10; tentative brand mismatch alongside sensitive inputs 15. VirusTotal malicious vendor counts contribute 45/65/85 for one/two/three or more engines. Safe Browsing matches contribute 85. Total score is capped at 100. See `risk_engine.py` for the full policy.

A lone account keyword, `eval`, missing mail records, HTTPS or third-party resource is not treated as proof. Missing services do not add risk. If HTML could not be inspected and there is no meaningful threat evidence, the **assessment is UNKNOWN**, even if the observed heuristic severity is SAFE/LOW. Target block/verification pages are recognized, including explicit block titles with HTTP 200. `partial`, `timeout`, `unreachable`, `dns_error`, `redirect_error`, `tls_error`, `blocked_destination`, `blocked_by_target` and unavailable-service states are displayed independently of severity.

Phishing DNA displays the actual awarded evidence points against each dimension's cap, with evidence IDs. These values are not invented percentages. Unavailable dimensions display unavailable. Even SAFE means no strong indicators were observed within stated coverage, not that a website is proven safe.

## SSRF and application protections

The website client only allows HTTP 80 / HTTPS 443. It rejects local/private/link-local/loopback/shared/reserved/multicast addresses, metadata hosts, Azure's platform endpoint, mixed public/private DNS answers and IPv6 transition/mapped/NAT64 destinations. TCP connects to a validated literal IP without resolving again; Host/SNI remain the original hostname. Every redirect is checked before connection. Target fetches do not use environment proxies, browser cookies or arbitrary authorization headers. Response cookies are omitted from saved headers. Compressed responses are bounded and incomplete compressed streams are rejected.

Connections try at most four already-vetted public IPs within one combined TCP deadline, preserving IP pinning and hostname verification. Exhausting that budget yields an explicit fetch failure. DNS resolution and external internet access must be available. Network-level egress restrictions provide an additional deployment safeguard.

Same-origin POST checks, safe result rendering, upload magic/type checks, request limits, separate scan/upload concurrency caps and standard response security headers are included. Existing inline scripts/styles require CSP `unsafe-inline`; stricter nonce-based CSP is a future improvement.

Scan history, cache entries, dashboard metrics, evidence and reports are scoped to a random visitor identifier in a signed, HttpOnly, SameSite cookie. Vercel uses a Secure `__Host-` cookie. Another visitor cannot retrieve a scan by knowing its ID or URL. There are no accounts or cross-device history recovery; losing the cookie or rotating `SECRET_KEY` loses access to that visitor history.

On Vercel, the trusted client-IP header is hashed with the server secret for an atomic database minute counter; raw client IPs are not stored in this counter. VirusTotal also has a shared outbound counter. Local mode additionally uses process limits and concurrency caps. A platform firewall can provide further abuse controls.

## Storage, crawler, dashboard and bulk scans

The preferred Vercel backend is Neon Postgres from the Vercel Marketplace. It stores complete schema-versioned evidence in JSONB plus indexed visitor/URL/time metadata and small dashboard summaries. `postgres_store.py` uses parameterized SQL, certificate- and hostname-verified TLS connections to the provider's pooled URL, transaction-local statement/lock timeouts compatible with Neon transaction pooling, serialized first-run schema initialization, 30-day retention and atomic rate counters. There are no background database queues or permanent application connection pools.

MongoDB remains supported as an alternative and uses `phishing_detection.verified_scans`, with the entire schema-versioned result. Legacy incomplete/mock records are not represented as verified scans. The Mongo client is reused, failing operations fall back to actual locally saved results, and outage retries are bounded.

Without a reachable configured database, local SQLite stores actual scans in `data/scans.sqlite3`, retaining roughly 30 days. This starts empty, never with fabricated examples. Vercel has an emergency `/tmp/phish-x-ai/scans.sqlite3` mirror, which is instance-local and ephemeral. New production scan/upload requests require a reachable durable database and stable secret. A database failure during a scan is disclosed; that browser result is not described as durably saved. Cached records include full features, evidence, timeline, graph, snapshot and AI status. Failed fetches are not served as completed cached scans; provider configuration changes invalidate cache eligibility.

The original crawler page now submits an actual seed URL, shows its measured stages and evidence, and optionally follows up to two discovered same-site links locally. It skips arbitrary query links and obvious logout/delete endpoints. It does not execute page scripts or crawl indefinitely. Local SocketIO emits to the submitting connection only. HTTP operation remains available without SocketIO. History refresh uses ordinary polling. On Home, the first-visit terminal and heading-decryption animation remain; returning or reloading in the same tab skips the intro and restores real completed results, URL drafts and bulk input through session storage. Restored browser state is never accepted as a backend security assessment.

Bulk scanning uses the same pipeline, with up to ten URLs locally and two concurrent scan tasks. It separates rejected inputs from actual completed/partial results. The dashboard summarizes stored observations, with unknown and partial counts and UTC date trends. Its history window is the latest 10,000 records; the crawler feed is the latest 50.

## APK and PDF analyzers

Both original upload screens remain. They perform bounded **static analysis**, not AI or exhaustive malware detection. Uploads use unique temporary directories and are removed after processing. Limits are 16 MiB locally, 4 MiB in Vercel mode, with a 16-second isolated worker timeout and two concurrent workers maximum. Workers also enforce CPU limits and a Linux memory limit; explicit worker failures do not produce invented findings.

APK analysis uses the current Androguard APK API to inspect manifest identity, SDK/version, permissions, debug/backup/cleartext settings, exported components and native libraries. ZIP expansion/entry limits apply. It does not execute Android code or analyze all DEX behavior. File/signature validity and suspicious permissions alone do not establish malware.

PDF analysis walks bounded PDF objects for JavaScript actions, URI/launch actions, embedded files and forms. It handles encryption/parse limits and reports unavailable analysis explicitly. It never executes embedded JavaScript or follows links. It does not provide full exploit detection or antivirus scanning.

Reports use the scan ID and measured evidence, including intelligence, crawler findings, score contributions, DNA, AI availability/explanation and timeline. Long table values are marked as excerpts rather than causing report layout failure.

## Vercel deployment

The project keeps `app.py` with the exported Flask `app`. `vercel.json` uses current Flask auto-discovery and a 60-second function limit. `prepare_vercel.py` copies the existing assets to `public/static`, preserving `/static/...` URLs for CDN serving. The local Flask static folder remains unchanged. See [Vercel's Flask documentation](https://vercel.com/docs/frameworks/backend/flask).

1. Create/import a Vercel project with this folder as its root. Keep the Flask framework detection, `app.py`, `.python-version`, `vercel.json`, `prepare_vercel.py` and requirements lock. Do not upload `.env`, local databases or virtual environments.
2. Open the project's **Storage** tab, choose **Create Database**, select **Neon**, and connect it to the project. Choose a database region near the function region. Vercel Marketplace provisions database credentials as environment variables. See [Vercel storage](https://vercel.com/docs/storage) and [Neon integration](https://vercel.com/marketplace/neon).
3. Use the **pooled** Neon connection as `DATABASE_URL` (normally its hostname contains `-pooler`). Add that same value to the local ignored `.env` to verify the database before deployment. Do not paste it into chat. The database role must be allowed to create the application's tables/indexes on first use. `POSTGRES_URL` is also accepted; MongoDB is unnecessary when Postgres is configured.
4. Add `SECRET_KEY`, `AI_PROVIDER=groq`, `GROQ_API_KEY`, `GROQ_MODEL=openai/gpt-oss-120b`, `VIRUSTOTAL_API_KEY` and `FLASK_DEBUG=False` in Vercel environment settings. Add Safe Browsing only if configured. Generate the secret with `python -c 'import secrets; print(secrets.token_hex(32))'` and keep it stable. No actual credentials belong in committed files.
5. Redeploy after setting environment variables. Visit `/api/readiness`: it must return HTTP 200, `ready: true`, and `storage: postgres`. This checks an actual database connection and provider configuration; a funded, successful AI call still needs a real scan. If it returns 503, fix the listed configuration issue.
6. In that deployment, scan a public site, visit the dashboard, return/reload, download its PDF, test the two-URL bulk scanner and upload controlled APK/PDF fixtures. Verify history/report retrieval after a cold start. Check real AI completion and configured threat-intelligence states. The real Preview passed scans, history/report retrieval, bulk/crawler HTTP flow and controlled APK/PDF workers. Browser restoration also passed locally. Production scans, storage, reports, bulk/crawler and file workers were also checked after PR #1 merged.

If no Vercel project exists yet, Neon can also be created directly in its dashboard; use its pooled Postgres connection locally, then connect/configure that database when creating the Vercel project. No Cloudflare service or Blob storage is needed for this implementation: reports are generated from saved evidence and uploads are temporary, rather than retained as public files.

`VERCEL` selects synchronous HTTP mode: no SocketIO server, background queue, post-response threads or scheduled crawler. Bulk scans are capped at two; linked-page crawling returns a clear limitation. API requests finish within bounded scan budgets. The platform may still time out cold starts, parsing or dependency-heavy file workers; callers get explicit failures where the runtime permits an HTTP response.

This Python Flask app uses HTTP on Vercel; Python SocketIO/WebSocket compatibility is not claimed. Uploads are capped below the documented [4.5 MB function request limit](https://vercel.com/docs/errors/function_payload_too_large), including multipart overhead. `/tmp` is temporary; Postgres or MongoDB provides durable evidence for reports/history across instances. A missing or inaccessible report returns 409. APK/PDF workers passed actual Vercel Preview and Production checks with controlled benign fixtures.

The configuration and serverless application mode were tested locally and on a real Vercel Preview. **A real free Neon pooled connection, complete scan persistence, retrieval from a fresh application instance, visitor isolation, atomic shared counters and stored-evidence PDF reports passed live checks. Groq, VirusTotal and stable session settings are configured for Vercel Preview/Production. An actual Vercel Preview build and hosted real GitHub scan (HTTP 200, parsed HTML, completed Groq/VT, durable Neon history, report and visitor isolation) also passed. Safe Browsing remains optional and unconfigured.** Local serverless-mode checks are separate from actual cloud execution.

## Data handling

The scanner sends the submitted URL to configured VirusTotal/Safe Browsing services and public DNS/RDAP providers. A configured AI provider receives structured scan evidence and a short page-text excerpt. Do not scan URLs containing private tokens or confidential data unless your service configuration and access controls allow that transmission. Uploaded APK/PDF files are analyzed locally in temporary workers and are not submitted to those services. The selected database contains URLs, page excerpts, headers without cookies, destinations and scan findings. History reads enforce a 30-day window; MongoDB TTL and bounded Postgres/SQLite cleanup remove expired records. Public HTML/static assets contain no service secrets. The supplied safe/red shields and matching amber warning shield identify observed assessments; UNKNOWN uses a neutral icon.

## Tests and audit

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Tests are offline, controlled fixtures in temporary databases, never seeded production security results. They cover SSRF, rebinding-resistant connections, redirects, response limits, scoring evidence, client verdict spoofing, full caching, report reuse, AI validation/failures, intelligence status handling, file checks, database fallback and serverless mode. See `AUDIT.md` for the original route audit and `VALIDATION.md` for actual localhost/browser/network observations and remaining configuration requirements.


### Public assets and release checks

The existing `static/` files remain the source. Matching `public/static/` copies are committed because Vercel discovers public assets before the Python build command runs. This keeps the same Jinja URLs and visual design while serving those files from the CDN. After editing an asset, run `python prepare_vercel.py` and commit both copies. CI runs `python prepare_vercel.py --check` to reject missing, stale or mismatched deployment assets.

GitHub Actions runs the regression suite, pinned dependency checks, Python compilation and JavaScript parsing on Linux/Python 3.12. `VALIDATION.md` records measured live checks. The release branch and draft PR allow Preview verification before merging to the production branch.


## Production performance and diagnostics

Production is published at https://phishxai.vercel.app/. After PR #1 merged, Vercel reported Ready, all six pages returned 200, and `/api/readiness` verified a real Neon connection. Fresh Google/GitHub scans completed actual HTML/DNS/TLS inspection, Groq reasoning and VirusTotal. The harmless AMTSO phishing test produced a measured warning; an initial Groq rate limit was explicitly unavailable. Complete evidence, session-scoped history, same-ID reports, bulk/crawler HTTP paths and both file workers passed Production checks. These are recorded observations, not future availability promises.

The Speed Insights screenshot shows the documentation framework selector, which defaults to Next.js. This project uses the official HTML integration instead: `templates/_performance.html` loads a small deferred initializer on Vercel Production only. It registers a `beforeSend` privacy hook before loading Vercel's same-origin collector. Only the seven known page paths are measured; query strings/fragments are removed. Scan URLs, input values, uploaded files and analysis results are not sent to Speed Insights. No telemetry runs locally or on Preview. Set `SPEED_INSIGHTS_ENABLED=false` to disable it. [HTML setup](https://vercel.com/docs/speed-insights/quickstart), [event filtering](https://vercel.com/docs/speed-insights/package).

Speed Insights measures page performance; adding it alone does not accelerate scans. The free tier currently provides RES and 10,000 events over a rolling 30-day window shared across the team, with collection paused at its limit and no event charges. Detailed individual Core Web Vitals require Plus; this project does not enable a paid upgrade. New collection needs actual visitor events before a useful score appears. [Limits and pricing](https://vercel.com/docs/speed-insights/limits-and-pricing).

Targeted loading fixes preserve the UI: logo dimensions reserve layout space, font connections start earlier, unused font/Bootstrap JavaScript downloads are removed, and Chart.js is version-pinned and deferred with initialization after DOM readiness. Its failure displays an honest chart-unavailable message while actual tables remain available.

AI context keeps measured facts as valid structured JSON, explicitly marks sampled text/lists and caps the evidence view at 12,000 characters. Long header values become presence observations; duplicate page text is removed. The stored/displayed ledger remains complete. A smaller completion budget reduces unnecessary quota reservation. Google/GitHub/AMTSO reasoning over actual evidence subsequently completed with validated citations. Groq's account-wide free token/request limits still apply, and any rate limit remains explicit. [Groq limits](https://console.groq.com/docs/rate-limits).


### AI warning citation boundaries

When any evidence contributes risk points, AI key-reason citations are restricted to those actual scoring records. Incidental scripts and absent headers cannot be cited as extra reasons for a warning. Complete observation-only records remain available as context and in the UI/report. Groq constrains explanations to qualitative prose; measured counts are displayed from the ledger instead of recalculated by the model. Validation rejects overstated vendor agreement or claims of confirmed malicious intent. A rejected Groq response may be regenerated by the actual service once within the same deadline, with at most two provider requests total; persistent failures are discarded, never replaced with invented AI text. Updated cache fingerprints prevent older-policy results from being reused as fresh scans. AI interpretations still require independent review.
