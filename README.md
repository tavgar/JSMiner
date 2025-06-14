# JSMiner

JSMiner began as a small command line tool for scraping JavaScript, HTML and related files to search for common patterns such as email addresses or JWT tokens. Over time it has grown into a more full-featured utility. The latest versions parse JavaScript into an AST to detect values stored in variables or built from string concatenation. The project is written in Go and distributed under the AGPL‑3.0 license.

## Building

```
go build ./cmd/jsminer
```

This produces a binary named `jsminer`.

## Usage

```
jsminer [URL|PATH|-] [flags]
```

Flags:

- `-format` output format, `pretty` or `json` (default `json`).
- `-safe` safe mode - ignore non-JS files and patterns that aren't JavaScript specific (default `true`).
- `-allow` allowlist file. Sources whose names end with any suffix listed in this file are ignored.
- `-rules` extra regex rules YAML file.
- `-output` write output to file instead of stdout.
- `-quiet` suppress startup banner.
- `-targets` file with additional URLs/paths to scan, one per line.

### Rule file format

The file supplied via `-rules` must be a YAML mapping where each key is the
pattern name and the value is a Go regular expression. The file is parsed using
[`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3). Example:

```yaml
phone: "\\d{3}-\\d{3}-\\d{4}"
ipv6: "[0-9a-fA-F:]+"
```
See `examples/rules.yaml` for a sample file.

A URL, filesystem path or `-` for stdin must be provided, or use `-targets` to supply multiple inputs. The program exits with status `1` when matches are found.

### Endpoint scanning

Package `scan` also exposes `Extractor.ScanReaderWithEndpoints` to collect
HTTP endpoint strings inside JavaScript sources. Endpoint matches are returned
with the pattern name `endpoint`.

## Testing

```
go test ./...
```

## License

This project is licensed under the terms of the GNU Affero General Public License v3.0. See the `LICENSE` file for more details.
