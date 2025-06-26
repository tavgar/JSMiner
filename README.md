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
- `-render` render pages with headless Chrome (default `true`, set `-render=false` to disable; Chrome/Chromium must be installed)
- `-longsecret` detect generic long secrets (disabled by default). Enable to
  search for high-entropy strings that may represent API keys.
- `-output` write output to file instead of stdout.
- `-quiet` suppress startup banner.
- `-targets` file with additional URLs/paths to scan, one per line.
- `-plugins` comma-separated list of Go plugins providing custom rules.
- `-header` HTTP header in `Key: Value` form. May be specified multiple times.

Using `-render` requires Chrome or Chromium to be installed on your system.

The binary includes a small set of **power rules** enabled by default. These
rules detect common items such as phone numbers, IPv6 addresses and generic
file paths. IPv6 matches are validated with Go's `net.ParseIP` to reduce false
positives. Supplying a file with `-rules` adds to this default set.

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

## Testing

```
go test ./...
```

## License

This project is licensed under the terms of the GNU Affero General Public License v3.0. See the `LICENSE` file for more details.
