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

## Usage

``` 
jsminer [flags] [URL|PATH|-] 
```

Flags may appear before or after the input path or URL.

Flags:

- `-format` output format, `pretty` or `json` (default `json`).
- `-safe` safe mode - ignore non-JS files and patterns that aren't JavaScript specific (default `false`).
- `-allow` allowlist file. Sources whose names end with any suffix listed in this file are ignored.
- `-rules` extra regex rules YAML file.
- `-endpoints` return only HTTP endpoints (default includes all matches)
- `-posts` return HTTP POST request endpoints with any parameters
- `-external` follow external scripts and imports (default `true`)
- `-crawl` crawl the in-scope endpoints and paths discovered on each page to
  reach more JavaScript files and secrets. Discovered `endpoint_url`,
  `endpoint_path` (and, with `-posts`, `post_url`/`post_path`) values that match
  the target host are fetched and scanned, and the endpoints they reveal are
  followed in turn until the depth or page budget is reached. Off-scope URLs are
  still reported but never crawled. Results are deduplicated before output.
- `-crawl-depth` max link hops to follow beyond the seed page (default `2`;
  `0` scans only the seed).
- `-crawl-max-pages` max pages to fetch during a crawl (default `200`, `0` for
  unlimited).
- `-ac` auto-calibrate the crawl (requires `-crawl`). Modeled on `ffuf -ac`:
  before crawling, JSMiner probes the target with a few random, non-existent
  paths to learn what its catch-all / soft-404 pages look like, then skips any
  crawled page that matches that fingerprint or byte-for-byte duplicates a page
  already scanned. Calibration is also done **per directory level**: the first
  time the crawl reaches a new level (e.g. `/api/`, `/docs/`) it probes that
  level with random paths and learns its own catch-all fingerprint, so a
  section-specific soft-404 that differs from the root is caught too. This keeps
  single-page-app shells and soft-404 responses from flooding the output with
  duplicate, low-value findings.
- `-render` render pages with headless Chrome (default `true`, set `-render=false` to disable; Chrome/Chromium must be installed)
- `-longsecret` detect generic long secrets (disabled by default). Enable to
  search for high-entropy strings that may represent API keys.
- `-output` write output to file instead of stdout.
- `-snippet` show a JS-prettified, syntax-highlighted code snippet around each
  finding. In `pretty` output the excerpt is beautified, colored and the matched
  value is emphasized (color is used only when writing to a terminal). In `json`
  output each record gains a beautified `snippet` field.
- `-quiet` suppress startup banner.
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
(images, fonts, media, archives) that cannot yield secrets, fetches each
resource at most once, and stops at `-crawl-depth` hops or `-crawl-max-pages`
pages. Progress is printed to stderr unless `-quiet` is set, and all findings are
deduplicated before output. Crawling issues real GET requests to discovered
endpoints, so use it only against targets you are authorized to test.

Many sites answer every unknown path with the same catch-all page — a
single-page-app shell or a soft-404 that returns `200`. Left unchecked, a crawl
follows all of them and reports the same findings over and over. Add `-ac` to
auto-calibrate against that behaviour:

```
jsminer -crawl -ac -endpoints https://example.com/
```

JSMiner first probes the host with random paths to fingerprint its catch-all
response, and probes each directory level it later reaches (`/api/`, `/docs/`, …)
to catch section-specific soft-404s that differ from the root. It then skips
crawled pages that match a fingerprint or duplicate a page already scanned, so
only unique, useful pages are mined.

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
Each match also includes a `severity` level.
When scanning a single input, the JSON output omits the `source` field.

### Endpoint scanning

Package `scan` exposes `Extractor.ScanReaderWithEndpoints` to collect HTTP
endpoint strings inside JavaScript sources. Endpoint matches are returned with
the pattern name `endpoint_url` for absolute URLs and `endpoint_path` for
relative paths. Endpoint extraction is enabled by default. Pass the
`-endpoints` flag to filter output to endpoints only. The extractor recognizes
protocol-relative references and relative paths beginning with `./` or `../`.
Cross-domain scripts and imports are followed by default. Pass `-external=false` to restrict scanning to the same domain.
Package `scan` also provides `Extractor.ScanReaderPostRequests` to capture
endpoints used in HTTP POST requests. The function returns any associated
parameters when available. Use the `-posts` flag to output only POST request
endpoints with their parameters.

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
