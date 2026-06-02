package report

import (
	"fmt"
	"strings"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
)

// PrintConsole prints all findings to stdout in a human-readable, color-coded format.
func PrintConsole(findings []SecurityFinding) {
	if len(findings) == 0 {
		fmt.Printf("%s✅  No security findings detected.%s\n", colorGreen, colorReset)
		return
	}

	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n",
		colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s  K8s Security Hardener — Findings Report (%d total)%s\n",
		colorBold, colorCyan, len(findings), colorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n",
		colorBold, colorCyan, colorReset)

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	printSummaryBar(counts)
	fmt.Println()

	for _, f := range findings {
		printFinding(f)
	}
}

func printSummaryBar(counts map[string]int) {
	fmt.Printf("  %sSummary:%s  ", colorBold, colorReset)
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if c, ok := counts[sev]; ok && c > 0 {
			fmt.Printf("%s%s: %d%s  ", severityColor(sev), sev, c, colorReset)
		}
	}
	fmt.Println()
}

func printFinding(f SecurityFinding) {
	color := severityColor(f.Severity)
	sep := strings.Repeat("─", 55)

	fmt.Printf("  %s%s%s\n", colorBold, sep, colorReset)
	fmt.Printf("  %s[%s]%s  %s%s%s  [%s]\n",
		color, f.Severity, colorReset,
		colorBold, f.RuleID, colorReset,
		f.Timestamp)
	fmt.Printf("  %sResource:%s  %s/%s\n", colorBold, colorReset, f.Namespace, f.Resource)
	fmt.Printf("  %sIssue:%s     %s\n", colorBold, colorReset, f.Description)
	fmt.Printf("  %sFix:%s       %s\n", colorBold, colorReset, f.Remediation)
	if f.AttackPath != "" {
		fmt.Printf("  %s⚡ Attack Path:%s %s%s%s\n", colorRed, colorReset, colorRed, f.AttackPath, colorReset)
	}
	fmt.Println()
}

func severityColor(s string) string {
	switch s {
	case SeverityCritical:
		return colorRed
	case SeverityHigh:
		return "\033[91m" // bright red
	case SeverityMedium:
		return colorYellow
	default:
		return colorCyan
	}
}
