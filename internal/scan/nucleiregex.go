package scan

import (
	"fmt"
	"regexp"
)

var nucleiRegexes = []string{
	`"?'zopim[_-]?account[_-]?key"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'zhuliang[_-]?gh[_-]?token"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'zensonatypepassword"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'zendesk[_-]?travis[_-]?github"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'yt[_-]?server[_-]?api[_-]?key"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'yt[_-]?partner[_-]?refresh[_-]?token"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'yt[_-]?partner[_-]?client[_-]?secret"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'yt[_-]?client[_-]?secret"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'yt[_-]?api[_-]?key"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'yt[_-]?account[_-]?refresh[_-]?token"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'yt[_-]?account[_-]?client[_-]?secret"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'yangshun[_-]?gh[_-]?token"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'yangshun[_-]?gh[_-]?password"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'www[_-]?googleapis[_-]?com"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	`"?'wpt[_-]?ssh[_-]?private[_-]?key[_-]?base64"?'[^\S\r\n]*[=:][^\S\r\n]*"?[\w-]+"?`,
	// ... truncated list ...
}

func init() {
	for i, pat := range nucleiRegexes {
		r := regexp.MustCompile(pat)
		name := fmt.Sprintf("nuclei_%d", i)
		RegisterRule(RegexRule{Name: name, RE: r, Severity: "info"})
	}
}
