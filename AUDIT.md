# Existing-code audit and repairs

The supplied `/Users/sanskarparab/Downloads/Phish-X-main` directory was inspected before editing. The original `app.py`, `features_extract.py`, all six templates (including every inline JavaScript/CSS section), `static/css/styles.css`, dependency list, Vercel config, README, `.env.example` and ignore rules were reviewed. An inventory and an untouched backup were created outside the deliverable. Uploaded/project text was treated as source material, not permission to override the user's request.

## Original route audit

| Route | Original issue / behavior | Final implementation |
| --- | --- | --- |
| `/`, `/index` | Home template; POST `/index` duplicated scanning/storage | Existing home retained; GET alias and POST shared verified scan pipeline |
| `/scan` | Separate analysis/cache paths; inconsistent error/schema handling | Structured evidence, bounded real crawl, deterministic score, optional AI, complete stored result |
| `/bulk_scan` | Duplicated processing and background database writes | Same pipeline per URL, bounded parallel tasks, per-input errors, complete results |
| `/extract_features` | Accepted client `is_phishing`, title/content; assigned fixed 15/80 score | Ignores client security claims and performs server analysis |
| `/get_data` | Returned seeded `mock_db` rows; persistence inconsistencies | Actual visitor-scoped summaries from Postgres/MongoDB/SQLite |
| `/download_report` | Started another feature/API analysis and used incomplete/default findings | Generates from the exact stored scan ID; missing scan returns 409 |
| `/dashboard` | Mixed string/bool verdicts, fake fallback rows, incompatible timestamp handling | Actual stored metrics, unknown/partial counts, UTC trends, original charts/tables |
| `/crawler` | Feed included client-provided/hardcoded verdicts and queue-based pseudo-crawl behavior | Existing screen plus real seed/limited linked-page crawl, measured stages and stored evidence |
| `/apk_analyzer`, `/analyze_apk` | Old Androguard API imports, shared upload names, limited cleanup/error handling | Existing UI; current APK API; static manifest analysis, size/ZIP limits, unique temporary worker |
| `/pdf_analyzer`, `/analyze_pdf` | Called nonexistent page JavaScript API; temporary file/error issues | Existing UI; PDF object/action inspection, explicit coverage, bounded temporary worker |
| `/learn` | Multiple handlers flipped each card repeatedly | Existing content and styling; one click handler and keyboard activation |

Added `/crawl`, `/api/capabilities`, `/api/readiness` and `/api/scans/<scan_id>` support the existing screens. Existing Flask/Jinja route architecture was preserved; no frontend framework or separate frontend project was introduced.

## Core failures repaired

- `check_content`, `check_dns` and `check_ssl` example return values were removed. Compatibility helpers delegate real analysis; the main scan reuses one fetched page/TLS connection.
- Unsafe outbound URL access was replaced by strict URL/DNS/public-IP validation and pinned sockets. Every redirect and selected script URL is validated. Loop limits, response/decompression limits and deadlines are enforced. Arbitrary JavaScript is never executed.
- The old VirusTotal fixed delay and fabricated/fallback counts were replaced by existing-report lookup, submission, bounded status polling, quota/cooldown handling and explicit error states.
- The old risk engine's broad keyword/domain assumptions were replaced with a source-backed evidence ledger and category caps. Keywords, HTTPS, `eval` and absent SPF/DMARC alone do not establish a verdict.
- Incomplete cached scores/features and seeded `mock_db` rows were eliminated from verified history. Postgres and MongoDB store full results and visitor-scoped summaries; local fallback is actual SQLite data. No example rows are inserted.
- Duplicate queues/background writes/cache-clearing timers were removed. Serverless execution does not depend on post-response work.
- Unsafe frontend result interpolation was replaced by escaped text/DOM construction. Untrusted targets are not embedded in executable HTML or opened as graph links. Bulk/history/crawler now display actual stored states.
- Reports no longer perform a second scan. Missing evidence and unavailable AI/intelligence remain explicit.
- The frontend's preloader no longer claims a database/API connection occurred. Its existing animation remains, with a shorter startup interval and reduced-motion handling.
- The requested creator footer links to the supplied portfolio, LinkedIn, GitHub and Gmail compose recipient. Contact uses plain-link styling. Obsolete placeholder/footer dialogs were removed.
- Old unbounded/incompatible dependency ranges were replaced with tested major-version bounds. Removed redundant WHOIS/PyMuPDF/PyPDF2/FPDF dependencies; RDAP/pypdf/ReportLab supply the used capabilities.
- Vercel configuration now uses Flask auto-discovery, original assets copied to the CDN path, bounded requests and explicit Python HTTP mode. Linked-page crawling and oversized bulk requests are rejected there.

## Frontend preservation

All six original template files and the original stylesheet remain. The sidebar, logo, red/dark identity, page structure, background art, spider asset, upload cards, flashcards and scanner controls remain recognizable. The original stylesheet was extended with result-card/responsive/focus rules. Scanner/crawler logic was extracted into two small plain-JavaScript files; there is no React/Next.js build.

SHA-256 comparison confirmed **all five original PNG assets are byte-for-byte unchanged**. Changes to existing templates are targeted result sections, truthful labels, functioning handlers and responsive behavior. Phone tests identified and corrected analyzer navigation overflow and scanner flex sizing.

## Final release repairs

- Real Groq reasoning with strict schema output, collected citation-ID enums, warning/coverage constraints and malformed/rate-limit failure handling. Visible page excerpts now have their own actual evidence source. Optional AI failure preserves deterministic results. A short Groq Retry-After can trigger one bounded retry.
- Session-scoped scan/cache/history/dashboard/report ownership prevents another visitor reading guessed IDs or URLs. Stable production secrets and Secure signed cookies preserve scope across function instances.
- Preferred Neon Postgres adapter stores full JSONB evidence and indexed summaries, uses bounded pooled connections with certificate/hostname verification, coordinates initial DDL, and enforces shared scan/VT minute counters. MongoDB compatibility and honest local SQLite remain.
- Production readiness checks a real database connection. Missing durable configuration blocks new production work; mid-scan outages are disclosed. No seeded or incomplete-score records are presented as completed scans.
- Home preserves completed evidence and input drafts across navigation/reload without re-running the intro or scan. The original first-visit terminal/decryption animation remains.
- Added the supplied safe shield, transparent red harmful shield and matching amber warning shield. UNKNOWN/error states use a neutral icon, never a stale safe verdict.
- Wide results fill available desktop content space; the relationship explorer shows selected real adjacency without dense crossing lines. Timeline rails were removed; bulk capsules/+/- spacing and original design remain. Vendor evidence is readable rather than a raw JSON paragraph.
- Malformed HTML destinations and Origin headers now produce measured findings or explicit rejection instead of exceptions. Upload workers enforce time/CPU/Linux-memory limits. Oversized requests reject before provider/database work.
- Python 3.12 and a resolved dependency lock were tested. Environment files, local data, caches and virtual environments are excluded from Vercel and distribution. PDF typographic punctuation is normalized to avoid unsupported glyph boxes; other unsupported text is retained as Unicode escapes.

## Deliberate limits and remaining deployment work

- A successful Groq AI stage is live-verified. The earlier OpenAI credit error remains supported as a truthful failure state; OpenAI is not the selected provider. Ollama has not been live-tested.
- A real Neon pooled endpoint passed certificate-verified connection, complete evidence persistence, fresh-instance retrieval/report generation, ownership isolation and atomic shared counters. Neon rejects startup statement_timeout options; each operation now applies SET LOCAL bounds inside its transaction. MongoDB and Safe Browsing remain untested optional alternatives. Database outage fallback also passed isolated tests.
- Actual Vercel deployment/cold starts, Linux bundle size, cloud network access and APK/PDF subprocess behavior require verification in the target project. Local serverless-mode tests do not prove those cloud outcomes.
- Static website/file inspection is bounded, does not execute remote JavaScript and does not establish malware proof or guaranteed safety. Vendor opinions and AI inferences can be wrong.
- Live SocketIO updates are also bound to the submitting visitor; a stale/foreign connection falls back to HTTP. Visitor cookies provide session isolation, not accounts or cross-device identity recovery. Browser session storage restores display state; the server uses only its stored evidence for reports.
- Existing inline scripts/styles retain CSP `unsafe-inline`; changing that would require a separate template nonce refactor.

See `README.md` for configuration/data flows/Neon setup and `VALIDATION.md` for measured results and remaining external checks.
