package output

import (
	"fmt"
	"strings"
)

func Banner(version string) string {
	red := "\x1b[31m"
	yellow := "\x1b[33m"
	green := "\x1b[32m"
	reset := "\x1b[0m"

	artLines := []string{
		"       _______           _",
		"      / / ___/____ ___  (_)___  ___  _____",
		" __  / /\\__ \\/ __ `__ \\/ / __ \\/ _ \\/ ___/",
		"/ /_/ /___/ / / / / / / / / / /  __/ /",
		"\\____//____/_/ /_/ /_/_/_/ /_/\\___/_/",
	}

	coloredArt := make([]string, len(artLines))
	for i, line := range artLines {
		coloredArt[i] = fmt.Sprintf("%s%s%s", green, line, reset)
	}

	art := strings.Join(coloredArt, "\n")
	versionLine := fmt.Sprintf("%sv%s%s", green, version, reset)
	coloredSlogan := fmt.Sprintf("%sBij\u00ee%s %s\u2605%s %sKurdistan%s", red, reset, yellow, reset, green, reset)
	return fmt.Sprintf("%s\n%s\nby Tevger Xan\u00ea (Tavgar El Ahmed)\n%s\n", art, versionLine, coloredSlogan)
}
