package report

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"os"
)

// ShipToFile appends each finding as a JSON line to the given log file.
// The Wazuh agent monitors this file via its localfile configuration.
func ShipToFile(findings []SecurityFinding, path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %q: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, finding := range findings {
		if err := enc.Encode(finding); err != nil {
			return fmt.Errorf("failed to encode finding: %w", err)
		}
	}
	return nil
}

// ShipToSyslog sends each finding as a JSON string over UDP syslog.
// addr should be in the form "host:port" (e.g., "wazuh-manager:514").
func ShipToSyslog(findings []SecurityFinding, addr string) error {
	writer, err := syslog.Dial("udp", addr, syslog.LOG_WARNING|syslog.LOG_DAEMON, "k8s-hardener")
	if err != nil {
		return fmt.Errorf("failed to connect to syslog at %q: %w", addr, err)
	}
	defer writer.Close()

	for _, finding := range findings {
		data, err := json.Marshal(finding)
		if err != nil {
			return fmt.Errorf("failed to marshal finding: %w", err)
		}

		switch finding.Severity {
		case SeverityCritical:
			err = writer.Crit(string(data))
		case SeverityHigh:
			err = writer.Err(string(data))
		case SeverityMedium:
			err = writer.Warning(string(data))
		default:
			err = writer.Info(string(data))
		}

		if err != nil {
			return fmt.Errorf("failed to write to syslog: %w", err)
		}
	}
	return nil
}
