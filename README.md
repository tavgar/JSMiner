# JSMiner

JSMiner began as a small command line tool for scraping JavaScript, HTML and related files to search for common patterns such as email addresses or JWT tokens. Over time it has grown into a more full-featured utility. The latest versions parse JavaScript into an AST to detect values stored in variables or built from string concatenation. HTTP requests now include a browser-style User-Agent header so more sites will serve their JavaScript correctly. The project is written in Go and distributed under the AGPL‑3.0 license.

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
- `-safe` safe mode - ignore non-JS files and patterns that aren't JavaScript specific (default `true`).
- `-allow` allowlist file. Sources whose names end with any suffix listed in this file are ignored.
- `-rules` extra regex rules YAML file.
- `-endpoints` also extract HTTP endpoints from JavaScript
- `-output` write output to file instead of stdout.
- `-quiet` suppress startup banner.
- `-targets` file with additional URLs/paths to scan, one per line.
- `-plugins` comma-separated list of Go plugins providing custom rules.

The binary includes a small set of **power rules** enabled by default. These
rules detect common items such as phone numbers, IPv6 addresses and generic
file paths. Supplying a file with `-rules` adds to this default set.

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

### Endpoint scanning

Package `scan` also exposes `Extractor.ScanReaderWithEndpoints` to collect
HTTP endpoint strings inside JavaScript sources. Endpoint matches are returned
with the pattern name `endpoint`. In addition to absolute URLs, the extractor
recognizes protocol-relative references and relative paths beginning with
`./` or `../`.

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
