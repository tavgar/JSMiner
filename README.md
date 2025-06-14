# JSMiner

JSMiner provides a small command line tool for scraping JavaScript, HTML and related files to search for common patterns such as email addresses or JWT tokens. The project is written in Go and distributed under the AGPL‑3.0 license.

## Building

```
go build ./cmd/findsomething-cli
```

This produces a binary named `findsomething-cli`.

## Usage

```
findsomething-cli [URL|PATH|-] [flags]
```

Flags:

- `-format` output format, `pretty` or `json` (default `json`).
- `-safe` safe mode - ignore non-JS files and patterns that aren't JavaScript specific (default `true`).
- `-allow` allowlist file. Sources whose names end with any suffix listed in this file are ignored.
- `-rules` extra regex rules YAML file.
- `-output` write output to file instead of stdout.
- `-quiet` suppress startup banner.

A URL, filesystem path or `-` for stdin must be provided. The program exits with status `1` when matches are found.

## Testing

```
go test ./...
```

## License

This project is licensed under the terms of the GNU Affero General Public License v3.0. See the `LICENSE` file for more details.
