```
       _______           _
      / / ___/____ ___  (_)___  ___  _____
 __  / /\__ \/ __ `__ \/ / __ \/ _ \/ ___/
/ /_/ /___/ / / / / / / / / / /  __/ /
\____//____/_/ /_/ /_/_/_/ /_/\___/_/
v0.01v
by Tevger Xanê (Tavgar El Ahmed)
Bijî Kurdistan
```
# JSMiner

JSMiner began as a small command line tool for scraping JavaScript, HTML and related files to search for common patterns such as email addresses or JWT tokens. Over time it has grown into a more full-featured utility. The latest versions parse JavaScript into an AST to detect values stored in variables or built from string concatenation. HTTP requests now include a browser-style User-Agent header so more sites will serve their JavaScript correctly. The project is written in Go and distributed under the AGPL‑3.0 license.

## Installation

```
go install github.com/tavgar/JSMiner/cmd/jsminer@latest
```

## Building

```
go build ./cmd/jsminer
```

This produces a binary named `jsminer`.

### Bundling Chromium

JSMiner renders pages in headless Chrome. So it works out of the box even where no
browser is installed, it ships with a Chromium: the first time a render is needed
it downloads the **current latest stable** [Chrome for Testing](https://googlechromelabs.github.io/chrome-for-testing/)
build into a per-user cache (`<user cache>/jsminer/browser/<version>/`) and reuses
it thereafter, always keeping to the latest version. Resolution order for the
render browser is:

1. `-chrome-path` / `$JSMINER_CHROME` (explicit override);
2. the latest managed Chromium (downloaded/cached) — unless `-no-download-browser`;
3. a Chromium bundled next to the `jsminer` binary (`./chromium/…`);
4. a Chrome/Chromium already on `PATH`.

To produce a **self-contained, offline bundle** — the binary plus a Chromium in a
single archive that needs no runtime download — run:

```
make bundle        # builds dist/jsminer and dist/chromium/
```

or directly:

```
jsminer -download-browser -browser-dest dist
```

Ship the resulting `dist/` directory together; JSMiner finds the co-located
`chromium/` automatically. Use `-no-download-browser` to forbid any runtime
download (bundle- or PATH-only), or `-download-browser` on its own to pre-populate
the managed cache.

## Usage

``` 
jsminer [flags] [URL|PATH|-] 
```

Flags may appear before or after the input path or URL.

Flags:

- `-format` output format, `pretty` or `json` (default `pretty`).
- `-safe` safe mode - ignore non-JS files and patterns that aren't JavaScript specific (default `false`).
- `-allow` allowlist file. Sources whose names end with any suffix listed in this file are ignored.
- `-rules` extra regex rules YAML file.
- `-endpoints` return only HTTP endpoints (default includes all matches)
- `-posts` return HTTP POST request endpoints with any parameters
- `-external` follow external scripts and imports (default `true`)
- `-redirect` follow HTTP redirects (default `false`). This is independent of
  `-external`: when disabled, a redirect is stopped before its destination is
  requested even when it points to the same host or a subdomain; when enabled,
  redirects may cross domains. The received page/response body and its inline
  findings are still scanned.
- `-full` enable full discovery mode. This is equivalent to combining
  `-crawl -crawl-passive -crawl-permute`; the normal crawl depth, page, passive
  and permutation limits still apply and can be adjusted with their individual
  flags.
- `-crawl` crawl the in-scope endpoints and paths discovered on each page to
  reach more JavaScript files and secrets. Discovered `endpoint_url`,
  `endpoint_path` (and, with `-posts`, `post_url`/`post_path`) values that match
  the target host are fetched and scanned, and the endpoints they reveal are
  followed in turn until the depth or page budget is reached. Off-scope URLs are
  still reported but never crawled. Results are deduplicated before output.
- `-crawl-depth` max link hops to follow beyond the seed page (default `2`;
  `0` scans only the seed).
- `-crawl-all` crawl to unlimited depth, following links until no new in-scope
  pages remain. Still bounded by `-crawl-max-pages`; pair with
  `-crawl-max-pages 0` to remove the page cap entirely. Overrides `-crawl-depth`.
- `-crawl-permute` reuse every discovered path under every discovered directory
  level on the same origin. When the crawl finds `/admin/panel` and has also seen
  the levels `/`, `/api/` and `/shop/`, it additionally tries
  `/api/admin/panel` and `/shop/admin/panel`. Paths and levels are combined
  retroactively, so a path found late is still tried under levels seen earlier.
  A small set of suffix variants can remove likely mount prefixes—for example,
  `/legacy/admin/config.js` can also produce `/api/admin/config.js`—and candidates
  are ranked so scripts, configuration files and cross-branch API paths spend the
  request budget before repeated prefixes such as `/api/api/...`. Query strings
  and encoded path components are retained. An origin must contribute at least
  two real path sources before permutations are emitted, avoiding speculative
  self-prefix requests from a lone URL. Off by default because it multiplies
  requests; bounded by `-crawl-permute-max`.
- `-crawl-permute-max` max permuted URLs admitted to the crawl (default `1000`,
  `0` for unlimited). Already-known, duplicate and template-suppressed candidates
  do not consume the cap. Permutation pools, cap usage and telemetry are included
  in crawl checkpoints.
- `-crawl-max-pages` max pages to fetch during a crawl (default `200`, `0` for
  unlimited). The crawl is breadth-first but, within each depth level, fetches
  higher-yield targets first — JS bundles and JSON/API responses, then
  extensionless routes, then rendered HTML pages — so when this cap cuts the
  crawl off the budget was spent on the pages most likely to carry secrets and
  endpoints.
- `-crawl-workers` how many pages to fetch and scan in parallel during a crawl
  (default `8`, `1` for a fully serial crawl). A crawl is dominated by per-page
  I/O — the HTTP fetch and, when rendering is on, a headless-Chrome render that
  can take seconds — so scanning several pages at once is the main speed-up.
  Per-host pacing and adaptive backoff (see `-rate-limit`) still bound the load
  any single host sees, so this stays polite. Note that with rendering on each
  busy worker runs its own browser, so higher values also cost more memory;
  lower it on constrained hosts or raise it for network-bound (non-render)
  crawls.
- `-crawl-resume` checkpoint file for a resumable crawl (default off). When set,
  the crawl periodically writes its whole recoverable state — pages visited, URLs
  still queued, matches found so far — to this file, and a later run with the same
  seed reloads it and continues instead of starting from zero. This makes a large
  `-crawl-all` survive being killed part way through. The file is written
  atomically and removed on clean completion; a checkpoint for a different seed is
  ignored so the crawl starts fresh.
- `-methods` comma-separated HTTP methods each crawled URL is probed with
  (default `GET,POST,PUT,PATCH,DELETE,OPTIONS`). The methods that work — judged
  against the per-method error logic learned by auto-calibration — are reported
  per URL in the [Gathered URLs](#gathered-urls) segment.
- `-no-methods` disable multi-method probing and gathered-URL reporting.
- `-no-param-replay` disable replaying discovered parameters across every
  discovered directory level.
- `-no-template-dedup` disable collapsing templated duplicate pages — pages that
  share a layout and differ only in data (`/product/1` vs `/product/2`,
  paginated listings, calendar/faceted URLs). See
  [Template deduplication](#template-deduplication) below.
- `-template-sample-max` how many representative pages to crawl per templated
  class when template dedup is on (default `3`).
- `-no-well-known` disable seeding a crawl from the site's own declarations. By
  default a crawl also fetches `robots.txt` (following its `Allow`/`Disallow`
  directories and `Sitemap:` pointers) and the XML sitemaps it and convention
  advertise, then enqueues those server-published URLs — reaching pages and API
  roots that nothing links to and that static JS scanning never reveals. The
  `robots.txt` `Crawl-delay` for the catch-all (`User-agent: *`) group is also
  honoured as a per-host pacing floor (clamped to 30s), combined with — never
  loosening — any `-rate-limit` you set. Disabling well-known discovery also
  stops the `Crawl-delay` from being read.
- `-crawl-passive` gather paths previously observed on the exact seed hostname
  from the Internet Archive Wayback CDX index and the latest Common Crawl index.
  Historical URLs are treated as untrusted hints: archived query values and
  fragments are discarded, paths are rebased onto the current seed origin, and
  each candidate must pass a live status and soft-404/catch-all check before it
  is scanned or allowed into the `-crawl-permute` path dictionary. Off by
  default because validation sends requests to the target.
- `-crawl-passive-sources` comma-separated passive indexes to query:
  `wayback,commoncrawl` (default both).
- `-crawl-passive-max` max sanitized historical path hints admitted for live
  validation (default `100`; values `<= 0` also select `100`, so third-party
  enumeration is never unbounded). The normal depth, page, template-dedup, scope
  and rate limits still apply.
- `-rate-limit` cap outbound HTTP at N requests per second across the whole scan
  (default `0`, no proactive limit). Independent of this, adaptive backoff is
  always on: a `429`/`503` response — seen on the Go request path or by the
  headless-Chrome renderer — widens the request spacing and honours the server's
  `Retry-After` before continuing, easing back to full speed once the host stops
  rate-limiting.
- `-http-timeout` per-request timeout in seconds for HTTP fetches — page and
  script fetches, calibration and method probes, sitemap downloads, and passive
  index lookups (default `10`). Raise it for enterprise crawls of large bundles
  over slow links; lower it so a single stalled request cannot hold up the
  crawl. Independent of the render wait controlled by `-timeout`.
- `-retries` extra attempts for a safe, bodyless HTTP read that fails with a transient
  transport error — a connection reset, DNS blip or timeout (default `2`, `0` to
  disable). Only GET/HEAD/OPTIONS reads are retried, so active
  POST/PUT/PATCH/DELETE probes and parameter replays are never re-sent; this keeps a crawl of
  thousands of requests from dropping pages to one-off network hiccups.
- `-no-source-maps` disable recovering original source from JavaScript source
  maps. By default, when a scanned bundle advertises a source map (via a
  `//# sourceMappingURL=` comment or a `SourceMap` / `X-SourceMap` response
  header), JSMiner recovers the original, pre-bundled source — from the map's
  embedded `sourcesContent` or by fetching in-scope original files — and scans
  it too, so secrets and endpoints that only survive in the un-minified source
  are reported through the normal output path.

  Crawls are always **auto-calibrated** (formerly the `-ac` flag, now the
  default): JSMiner probes the target — and each directory level it reaches — with
  random, non-existent paths to learn its catch-all / soft-404 fingerprints, then
  skips any crawled page that matches a fingerprint or byte-for-byte duplicates a
  page already scanned. This keeps single-page-app shells and soft-404 responses
  from flooding the output with duplicate, low-value findings. See
  [Auto-calibration](#auto-calibration) below.
- `-render` render pages with headless Chrome (default `true`, set `-render=false` to disable; Chrome/Chromium must be installed)
- `-chrome-path` explicit path to the Chrome/Chromium executable used for
  rendering. Overrides the bundled/downloaded browser; also honours the
  `JSMINER_CHROME` environment variable. Use it to force a specific browser.
- `-no-download-browser` never download a Chromium; render only with
  `-chrome-path`, a bundled or previously cached browser, or one on `PATH`.
- `-download-browser` provision the managed Chromium now (downloading the latest
  stable build if needed) and print its path, then exit if no target is given.
  Combine with `-browser-dest <dir>` to extract into `<dir>/chromium` for a
  self-contained bundle (see [Bundling Chromium](#bundling-chromium)).
- `-longsecret` detect generic long secrets (disabled by default). Enable to
  search for high-entropy strings that may represent API keys.
- `-output` write output to file instead of stdout.
- `-snippet` show a JS-prettified, syntax-highlighted code snippet around each
  finding. In `pretty` output the excerpt is beautified, colored and the matched
  value is emphasized (color is used only when writing to a terminal). In `json`
  output each record gains a beautified `snippet` field.
- `-quiet` suppress startup banner.
- `-v` / `-vv` / `-vvv` verbose logging to stderr, cumulative — each level adds to
  the ones below it (see [Verbose output](#verbose-output)). `-v` prints the crawl
  narrative (matches per page, in-scope targets discovered, calibration and
  template-dedup skips); `-vv` also logs every HTTP request with its method,
  status and each page render; `-vvv` adds a per-item trace (target enqueue/skip
  decisions, method probes, parameter replays, permutations, followed imports).
  Diagnostics go to stderr so they never mix into the results on stdout.
- `-proxy` run as HTTP/HTTPS proxy on the specified address (e.g. `:8080`).
- `-targets` file with additional URLs/paths to scan, one per line.
- `-plugins` comma-separated list of Go plugins providing custom rules.
- `-insecure` skip TLS certificate verification for HTTPS requests (default `true`).
- `-header` HTTP header in `Key: Value` form. May be specified multiple times.

Using `-render` requires Chrome or Chromium to be installed on your system.

### Crawl mode

A single page rarely links every JavaScript bundle a site ships. Pass `-crawl`
to turn a one-page scan into a breadth-first crawl: JSMiner scans the seed,
harvests the in-scope endpoints it finds, fetches those, and repeats — reaching
bundles that are only linked from deeper pages or returned by API routes, and
mining them for secrets too.

```
jsminer -crawl -crawl-depth 2 -endpoints https://example.com/
```

The crawl stays on the target host and its subdomains, skips binary assets
(images, fonts, media, archives — by URL extension *and* by response
`Content-Type`, so an extensionless URL that returns an image or PDF is skipped
too) that cannot yield secrets, fetches each resource at most once over a pooled
keep-alive connection, retries transient network errors on safe reads
(see `-retries`), and stops at `-crawl-depth` hops or `-crawl-max-pages` pages.
Progress is printed to stderr unless `-quiet` is set, followed by a one-line
run summary — pages fetched, errors, targets discovered, pages enqueued, matches
and elapsed time — and all findings are deduplicated before output. Crawling issues real requests to discovered
endpoints — including non-`GET` methods (`POST`, `PUT`, `PATCH`, `DELETE`,
`OPTIONS`) for method probing and parameter replay — so use it only against
targets you are authorized to test. Pass `-no-methods` to restrict a crawl to
`GET` requests only.

### URL discovery

JSMiner pulls candidate URLs from every place a modern app hides them, so a crawl
follows the real link graph instead of only what one page happens to reference in
one form:

- **JavaScript** — endpoints and paths in inline scripts, linked bundles and
  dynamic `import()`s, including template-literal bases (`` `/api/user/${id}` `` →
  `/api/user/`) and bare-relative request paths in call context
  (`fetch("api/search?q=" + q)` → `api/search`). WebSocket and SSE endpoints
  (`new WebSocket("wss://…")`, `EventSource("/stream")`) are surfaced too,
  including their bare-relative forms.
- **HTML assets** — beyond the navigational attributes below, `srcset` candidates
  on `<img>`/`<source>` and CSS `url(…)` references in `<style>` blocks and inline
  styles, where a config or data path occasionally hides.
- **JSON API responses** — when a crawled endpoint returns JSON, its hypermedia
  links (`href`/`self`/`next`, JSON:API `links`, HAL `_links`) are followed to
  reach paginated and related resources nothing else references. Endpoint
  extraction keys on the content, so this works even for an extensionless API URL.
- **`Link:` response headers** — RFC 8288 web-linking headers
  (`Link: <…>; rel="next"`), the header form of the hypermedia links above and the
  dominant pagination mechanism for header-driven REST APIs. Navigable relations
  are followed; asset/hint relations (`stylesheet`, `preload`, `self`, …) are not.
- **GraphQL** — a discovered `/graphql` (or `/graphiql`) endpoint is confirmed
  with an introspection query; when introspection is enabled the schema surface is
  reported as a `graphql_introspection` finding (a misconfiguration worth
  flagging). Runs under active probing; disable with `-no-methods`.
- **Live requests** — the XHR/`fetch` URLs the page actually calls while rendering
  in headless Chrome, so endpoints built at runtime (from an id, a router param, a
  template) that appear in no shipped string are still reached.
- **HTML markup** — the URLs a page's own markup references: `href`, `src`,
  `action`/`formaction`, `data-url`/`data-href`/`data-src`, and
  `<meta http-equiv="refresh">` redirects. Relative links are resolved against the
  page, and unresolved template placeholders (`${…}`, `{{…}}`, `<%…%>`) are
  skipped. This is what lets the crawl follow a server-rendered or classic
  multi-page site, whose pages link one another through plain HTML rather than JS.
- **Site declarations** — `robots.txt` (`Allow`/`Disallow` directories and
  `Sitemap:` pointers) and the XML sitemaps it and convention advertise, including
  gzipped (`sitemap.xml.gz`) and nested sitemap-index documents. These surface
  server-published pages and API roots that nothing links to. Disable with
  `-no-well-known`.
- **`.well-known` metadata** — the standardized `.well-known` URIs (RFC 8615) a
  site publishes about itself: the OAuth 2.0 / OpenID Connect discovery documents
  (`openid-configuration`, `oauth-authorization-server`), which enumerate a
  provider's entire authorization/token/JWKS/userinfo endpoint surface; the mobile
  deep-link manifests (`apple-app-site-association`, `assetlinks.json`), which map
  app-backing API routes; and `security.txt`, `nodeinfo` and `host-meta`. Probed on
  every crawl alongside the site declarations above; disable with `-no-well-known`.
- **Passive web indexes (opt-in)** — `-crawl-passive` asks Wayback CDX and/or
  Common Crawl for URLs historically seen on the exact seed hostname. Only the
  path is retained and rebased onto the live origin; historical queries are not
  replayed. Candidates are ranked toward scripts, configuration and API paths,
  then validated on the live target before scanning. A 2xx/3xx response (or a
  route-proving 401/403/405) must also differ from the directory's calibrated
  catch-all response. Validated paths can enrich `-crawl-permute`; rejected and
  soft-404 paths cannot.
- **Source maps** — original, pre-bundled sources recovered from any source map a
  scanned bundle advertises (see [Source map recovery](#source-map-recovery)).

Passive index lookups use a public-data request path that never forwards values
from `-header`, so target cookies and authorization tokens are not disclosed to
Wayback or Common Crawl. Gathering is passive with respect to the target, but
the validation phase is active and consumes the normal crawl page/request budget:

```
jsminer -full -render=false https://example.com/
jsminer -crawl -crawl-passive -crawl-passive-sources wayback -crawl-passive-max 50 https://example.com/
```

### Rate limiting

A crawl issues many requests per page — the page fetch and render, multi-method
probing, per-directory and per-method auto-calibration, parameter replay and path
permutation — which can trip a target's rate limiter. That is not just a politeness
problem: once a host starts answering `429`, a page that would have revealed a
secret is instead returned as an error shell, so tripping the limiter *loses
findings*. JSMiner paces itself **per host** to stay under those limits without
dropping or reordering any request, so accuracy and secret recall are unaffected:

- **Budget-aware pre-emption (always on).** Servers that rate-limit almost always
  advertise the remaining budget and its reset in response headers — the
  `RateLimit-*` draft standard and the `X-RateLimit-*` / `X-Rate-Limit-*` vendor
  variants (`Remaining`, `Reset`). JSMiner reads these on every response and spreads
  the remaining requests across the reset window, slowing down *as it approaches*
  the limit so it never actually trips one. With none remaining it holds until the
  window resets (bounded by the backoff ceiling).
- **Adaptive backoff (always on).** When any request — on the HTTP path or in the
  headless-Chrome renderer — comes back `429 Too Many Requests` or `503`, JSMiner
  widens the spacing for that host and honours the server's `Retry-After` hint
  (delta-seconds or HTTP-date) before continuing, then eases back to full speed
  once the host stops rate-limiting. Backoff is tracked per host, so a slow host
  never throttles requests to an unrelated one.
- **Proactive limit (opt-in).** Pass `-rate-limit N` to cap outbound requests at
  `N` per second per host.
- **Jitter (opt-in).** Pass `-rate-limit-jitter F` (e.g. `0.2`) to randomise each
  inter-request gap by ±F, breaking up the perfectly regular cadence that some edge
  rate limiters flag as bot-like.

### Verbose output

By default a crawl prints one progress line per page to stderr (unless `-quiet`).
To see exactly what the crawler is doing, raise the verbosity with `-v`, `-vv` or
`-vvv`. The levels are cumulative — each includes everything below it — and all
diagnostics go to stderr, so the results on stdout stay clean and pipeable.

| Level  | Prefix  | What it adds                                                                                       |
| ------ | ------- | -------------------------------------------------------------------------------------------------- |
| `-v`   | `[v]`   | Crawl narrative: matches found per page, in-scope targets discovered, calibration and template-dedup skips, soft-404/duplicate skips. |
| `-vv`  | `[vv]`  | Network and render activity: every HTTP request with its method and status (fetches, calibration probes, method probing, replays) and every page render (scripts and application states surfaced). |
| `-vvv` | `[vvv]` | Per-item trace: individual target enqueue/skip decisions (with reason), method-probe results, parameter replays, cross-level permutations, and followed JS imports.                                 |

```
jsminer -crawl -vv https://example.com/           # follow the requests as they go out
jsminer -crawl -vvv https://example.com/ 2>trace.log   # capture a full trace, keep JSON on stdout
```

Because the log is on stderr, `2>trace.log` (or `2>/dev/null`) separates it from
the findings on stdout.

### Auto-calibration

Many sites answer every unknown path with the same catch-all page — a
single-page-app shell or a soft-404 that returns `200`. Left unchecked, a crawl
follows all of them and reports the same findings over and over. Every crawl is
auto-calibrated against that behaviour (this was the `-ac` flag; it is now the
default and always on):

```
jsminer -crawl -endpoints https://example.com/
```

JSMiner first probes the host with random paths to fingerprint its catch-all
response, and probes each directory level it later reaches (`/api/`, `/docs/`, …)
to catch section-specific soft-404s that differ from the root. It then skips
crawled pages that match a fingerprint or duplicate a page already scanned, so
only unique, useful pages are mined.

Auto-calibration also learns the catch-all fingerprint **per request method**:
the same `/api/` level can answer unknown `GET`s with a `404` shell and unknown
`POST`s with a `405` shell, and each is learned separately. This per-method error
logic is what decides which verbs count as "working" for the Gathered URLs
segment below.

### Template deduplication

Many sites expose the same page template over an unbounded key space —
`/product/1`, `/product/2`, …; `?page=1`, `?page=2`, …; calendar and faceted
URLs that differ only in a date or filter. These pages are structurally
identical and differ only in their data, so crawling every instance burns the
page budget without finding anything new. Exact-body and coarse (status /
word-count / line-count) signatures do not catch them, because each instance has
a genuinely different body.

Template deduplication (on by default) recognises these as one class and keeps
only a representative few — `-template-sample-max`, default `3` — so the budget
is spent on genuinely distinct pages:

```
jsminer -crawl https://example.com/            # dedups templates automatically
jsminer -crawl -template-sample-max 5 https://example.com/
jsminer -crawl -no-template-dedup https://example.com/   # visit every instance
```

It works on two levels. Discovered URLs are grouped by a normalised **URL
template** — numeric ids, UUIDs, dates and hashes in the path are generalised,
and query strings are reduced to their parameter names — *before* they are
fetched, so suppressed instances cost neither a request nor a page-budget slot.
Fetched pages are then grouped by a **structural body signature** (the page's
HTML tag skeleton, with repeat counts bucketed so a listing of 18 rows and one
of 22 match), catching templated pages whose URLs give no hint they are related,
such as slug-keyed pages. A few representatives of each class are still visited,
so an instance whose data — and therefore its secrets — differs from its
siblings is not missed outright.

### Gathered URLs

During a crawl JSMiner probes every URL it visits with each method from
`-methods` (by default `GET,POST,PUT,PATCH,DELETE,OPTIONS`) and records the verbs
that genuinely work — a non-error response that does not match the level's learned
per-method catch-all. Each such URL becomes a **gathered-URL** finding, shown as
its own segment beneath the normal JavaScript findings:

```
$ jsminer -crawl -render=false -format pretty https://example.com/
[endpoint_path] (info) /api/submit

=== Gathered URLs ===
[gathered_url] (info) https://example.com/          params=methods=GET,OPTIONS
[gathered_url] (info) https://example.com/api/submit params=methods=GET,POST
```

In `json` output the gathered URLs use the `gathered_url` pattern and are ordered
after the normal findings, with the working methods in the `params` field.

Any parameters JSMiner discovers on `POST`/`PUT`/`PATCH` endpoints are also
**replayed across every directory level** the crawl has seen (bounded by an
internal cap): a body found under `/api/` is retried under `/`, `/v2/`, and every
other level, and a replay that works against that level's per-method error logic
is reported as a gathered URL with the parameters that produced it. Those
parameters come both from the request bodies mined out of JavaScript and from the
**field names of `POST` forms** in a page's HTML markup (`<input>`/`<select>`/
`<textarea>`/`<button>` `name`s), so form inputs that appear nowhere in the site's
scripts are exercised too. Pass `-no-methods` to turn the whole segment off, or
`-no-param-replay` to keep method probing but skip the cross-level parameter replay.

### Code snippets

Pass `-snippet` to show where each finding lives in the source. Minified or
single-line bundles are beautified into readable, indented lines, JavaScript
syntax is colored, and the matched value is highlighted:

```
$ jsminer -format pretty -snippet app.min.js
[google_api] (info) AIzaSyA1234567890abcdefghijklmnopqrstuvw
    ┌─ snippet ─────────────────────────────
     1 │ function initApp(cfg){
     2 │   const apiKey="AIzaSyA1234567890abcdefghijklmnopqrstuvw";
     3 │   fetch("/api/v1/login",{
     4 │     headers:{Authorization:"Bearer …"}
     5 │   }).then(r=>r.json());
     6 │ }
    └────────────────────────────────────────
```

Colors are emitted only when writing to a terminal, so redirected or piped
output stays plain. In `json` mode the beautified excerpt is added as a
`snippet` field on each record instead.

The binary includes a small set of **power rules** enabled by default. These
rules detect common items such as phone numbers, IPv6 addresses and generic
file paths. IPv6 matches are validated with Go's `net.ParseIP` to reduce false
positives. Supplying a file with `-rules` adds to this default set.

### False-positive filtering

Minified JavaScript bundles are dense with short identifiers, object literals,
SVG path data and CSS pseudo-selectors that superficially resemble secrets,
addresses and endpoints. To keep the output actionable, matches from the broad
built-in rules are validated before being reported:

- **Credential/keyword rules** (`password`, `token`, `api_key` and the generic
  nuclei `keyword: value` patterns) require the value to look like a real secret
  — long enough and not a minified identifier, boolean flag (`!0`), language
  keyword (`function`), kebab-case config name (`css-var-root`) or built-in
  (`Object`). Strict, self-describing formats (AWS keys, GitHub PATs, JWTs,
  bearer tokens, …) are matched unchanged.
- **HTTP headers** are separated from the object literals, CSS declarations and
  framework directives that share the `name: value` shape. A name that
  identifies itself — `Authorization`, `Content-Type`, `Referer`, or anything
  `X-`-prefixed — is reported wherever it appears. A name that does not is
  reported only inside a header map: `age`, `date`, `host`, `origin` and
  `accept` are registered headers *and* everyday object keys, so `{name:"Ada",
  age:30}` is not a header while `fetch(u,{headers:{age:"30"}})` is. Enclosure
  is established structurally rather than by proximity, so the `body:{age:30}`
  after a `headers:{…}` map does not inherit its context.
- **IPv4** uses a strict dotted-quad (octets 0–255, no leading zeros) and is
  rejected when it sits inside a longer decimal stream, which is how SVG
  coordinates and version arrays appear (`38.13.44.25.57…`, `1.11.16.2 57.17…`).
- **IPv6** must parse as a real, non-loopback address with at least three hextet
  groups, discarding CSS fragments such as `::before` → `::bef`.
- **Endpoints** drop regex/HTML fragments (`/([^/]+)`, `/></svg>`), placeholder
  and loopback URLs (`https://...`, `http://localhost`) and well-known
  documentation/library domains (react.dev, github.com, …) that are references
  rather than the target's own endpoints.

The net effect is a ~95% reduction in noise from the broad rules on typical
minified sites while genuine keys, tokens, addresses and API paths are retained.

### Rule file format

The file supplied via `-rules` must be a YAML mapping where each key is the
pattern name and the value is a Go regular expression. The file is parsed using
[`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3). Example:

```yaml
phone: "\\d{3}-\\d{3}-\\d{4}"
ipv6: "[0-9a-fA-F:]+"
path: "(?:/[A-Za-z0-9._-]+)+|[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+"
```
See `examples/rules.yaml` for a sample file.

A URL, filesystem path or `-` for stdin must be provided, or use `-targets` to supply multiple inputs. The program exits with status `1` when matches are found.

Each match includes a `severity` level and findings are returned ranked from
highest to lowest severity:

- `high` — distinctive credential formats (provider tokens, cloud keys, JWTs)
  whose signature alone makes a match almost certainly a live secret.
- `medium` — keyword-anchored credentials (`api_key = ...`, `password: ...`)
  that are probable secrets but carry more false positives and warrant review,
  and HTTP headers (`http_header`), which reveal the API's authentication scheme
  and internal routing conventions.
- `info` — non-secret intelligence such as endpoints, URLs, emails, paths and
  IPs.

Within a severity band, discovery order is preserved. Gathered URLs are shown as
their own segment beneath the ranked findings.
When scanning a single input, the JSON output omits the `source` field.

Every completed scan also returns a SHA-256 checksum of its full logical result
set and the UTC time at which the scan began. The checksum is based on each
result's pattern, value, parameters and severity; it is independent of discovery
order, source display and optional snippets, so equivalent result sets have the
same checksum. Pretty output ends with both values on one `[scan]` summary line.
JSON output returns an envelope:

```json
{
  "checksum": "3a8f…",
  "scan_time": "2026-07-17T07:08:09Z",
  "results": []
}
```

The metadata and `results` array are returned even when a scan finds nothing.
JSON mode suppresses the decorative banner automatically so the envelope remains
a valid JSON document; `-quiet` is not required for structured output.

### Endpoint scanning

Package `scan` exposes `Extractor.ScanReaderWithEndpoints` to collect HTTP
endpoint strings inside JavaScript sources. Endpoint matches are returned with
the pattern name `endpoint_url` for absolute URLs and `endpoint_path` for
relative paths. Endpoint extraction is enabled by default. Pass the
`-endpoints` flag to filter output to endpoints only. The extractor recognizes
protocol-relative references and relative paths beginning with `./` or `../`.
Cross-domain scripts and imports are followed by default. Pass `-external=false`
to restrict those page-referenced sources to the same domain. This setting does
not control redirects; use `-redirect=true` to follow HTTP redirects.
Package `scan` also provides `Extractor.ScanReaderPostRequests` to capture
endpoints used in HTTP POST requests. The function returns any associated
parameters when available. Use the `-posts` flag to output only POST request
endpoints with their parameters.

### Source map recovery

Production JavaScript ships minified and transpiled, so the secrets and
endpoints that were readable in the original source often survive only inside a
**source map** the bundle still advertises. JSMiner recovers them automatically:
whenever a scanned bundle points at a source map — through a
`//# sourceMappingURL=` (or legacy `//@`) comment or a `SourceMap` /
`X-SourceMap` response header — the map is loaded (decoded inline from a `data:`
URI, or fetched) and every original source it carries is scanned with the same
rules as everything else.

The map's embedded `sourcesContent` is used when present; when a source ships
separately, JSMiner fetches the original file if it resolves to an in-scope
`http(s)` URL (virtual paths such as `webpack://` are skipped). Recovered
findings are attributed to their original source path (e.g.
`webpack:///src/config.js`) and flow through the normal output, so a scan of a
minified bundle can surface a JWT or API path that never appears in the bundle
itself. Recovery is on by default and works for plain scans, `-crawl`, and
`-posts`; pass `-no-source-maps` to turn it off.

### Plugins

Additional rules can be compiled as Go plugins. Build the plugin with

```
go build -buildmode=plugin -o entropy.so ./examples/entropy
```

Load it at runtime with the `-plugins` flag:

```
jsminer -plugins entropy.so file.js
```

See `examples/entropy` for a simple entropy based rule.

### Proxy mode

Running with `-proxy` starts an HTTP/HTTPS proxy that scans traffic as you
browse. Configure your browser to use the proxy address and trust the proxy's
certificate to intercept HTTPS responses.

1. Download the CA certificate used by [goproxy](https://github.com/elazarl/goproxy) with:

   ```bash
   curl -L https://raw.githubusercontent.com/elazarl/goproxy/v1.7.2/ca.pem -o goproxy-ca.pem
   ```

   Alternatively, generate your own CA and replace this file.
2. Import `goproxy-ca.pem` into your browser's **Authorities** certificate store.
   - **Firefox:** Settings → Certificates → View Certificates… → Authorities → Import.
   - **Chrome:** Settings → Privacy and Security → Security → Manage certificates → Authorities → Import.
3. Start the proxy:

   ```bash
   jsminer -proxy :8080
   ```

Matches will stream to stdout or to the file specified with `-output`.

## Testing

```
go test ./...
```

## License

This project is licensed under the terms of the GNU Affero General Public License v3.0. See the `LICENSE` file for more details.
