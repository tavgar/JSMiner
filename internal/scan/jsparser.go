package scan

// extractJSStrings returns string and template literal contents from JavaScript source.
// This is a very small tokenizer used in place of a full JS parser.
func extractJSStrings(data []byte) []string {
	var strs []string
	for i := 0; i < len(data); {
		c := data[i]
		if c == '"' || c == '\'' {
			quote := c
			start := i + 1
			i++
			for i < len(data) {
				if data[i] == '\\' {
					i += 2
					continue
				}
				if data[i] == quote {
					strs = append(strs, string(data[start:i]))
					i++
					break
				}
				i++
			}
			continue
		}
		if c == '`' {
			start := i + 1
			i++
			for i < len(data) {
				if data[i] == '\\' {
					i += 2
					continue
				}
				if data[i] == '`' {
					strs = append(strs, string(data[start:i]))
					i++
					break
				}
				i++
			}
			continue
		}
		i++
	}
	return strs
}
