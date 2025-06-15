package output

import "fmt"

func Banner(version string) string {
	red := "\x1b[31m"
	green := "\x1b[32m"
	yellow := "\x1b[33m"
	reset := "\x1b[0m"
	art := `       _______ __  ____
      / / ___//  |/  (_)___  ___  _____
 __  / /\__ \/ /|_/ / / __ \/ _ \/ ___/
/ /_/ /___/ / /  / / / / / /  __/ /
\____//____/_/  /_/_/_/ /_/\___/_/`
	coloredSlogan := fmt.Sprintf("%sBij\u00ee%s %s\u2605%s %sKurdistan%s", red, reset, yellow, reset, green, reset)
	return fmt.Sprintf("%s\n\nby Tevger Xan\u00ea (Tavgar El Ahmed)\n%s\nversion %s\n", art, coloredSlogan, version)
}
