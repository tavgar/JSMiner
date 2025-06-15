package output

import (
	"fmt"
	"strings"
)

func Banner(version string) string {
	red := "\x1b[31m"
	white := "\x1b[37m"
	green := "\x1b[32m"
	yellow := "\x1b[33m"
	reset := "\x1b[0m"

	artLines := []string{
		"       _______ __  ____",
		"      / / ___//  |/  (_)___  ___  _____",
		" __  / /\\__ \\/ /|_/ / / __ \\/ _ \\/ ___/",
		"/ /_/ /___/ / /  / / / / / /  __/ /",
		"\\____//____/_/  /_/_/_/ /_/\\___/_/",
	}

	coloredArt := make([]string, len(artLines))
	for i, line := range artLines {
		var color string
		switch {
		case i < 2:
			color = red
		case i == 2:
			color = white
		default:
			color = green
		}
		coloredArt[i] = fmt.Sprintf("%s%s%s", color, line, reset)
	}

	coloredSlogan := fmt.Sprintf("%sBij\u00ee%s %s\u2605%s %sKurdistan%s", red, reset, yellow, reset, green, reset)
	art := strings.Join(coloredArt, "\n")
	return fmt.Sprintf("%s\nby Tevger Xan\u00ea (Tavgar El Ahmed)\n%s\nversion %s\n", art, coloredSlogan, version)
}
