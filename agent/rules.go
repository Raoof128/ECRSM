package main

import (
	"bytes"
	"strings"
)

// Alert represents a raised security signal.
type Alert struct {
	RuleID         string       `json:"rule_id"`
	Severity       string       `json:"severity"`
	RiskScore      int          `json:"risk_score"`
	Reason         string       `json:"reason"`
	Recommendation string       `json:"recommendation"`
	Event          RuntimeEvent `json:"event"`
}

var reverseShellPorts = map[uint16]struct{}{4444: {}, 8081: {}, 9001: {}}
var reverseShellBins = map[string]struct{}{"bash": {}, "sh": {}, "zsh": {}, "python": {}}

// EvaluateRules runs the rule set on an enriched event.
func EvaluateRules(evt RuntimeEvent) []Alert {
	var alerts []Alert
	if a, ok := detectReverseShell(evt); ok {
		alerts = append(alerts, a)
	}
	if a, ok := detectInjection(evt); ok {
		alerts = append(alerts, a)
	}
	if a, ok := detectSuspiciousExec(evt); ok {
		alerts = append(alerts, a)
	}
	return alerts
}

func detectReverseShell(evt RuntimeEvent) (Alert, bool) {
	comm := toString(evt.Comm[:])
	et := toString(evt.EventType[:])

	if et != "connect" {
		return Alert{}, false
	}

	port := ntohs(evt.DstPort)
	_, portFlag := reverseShellPorts[port]
	_, binFlag := reverseShellBins[comm]
	nonRoot := evt.UID != 0

	if (portFlag || binFlag) && nonRoot {
		reason := "reverse shell signature: outbound connect from shell binary"
		if portFlag {
			reason = "reverse shell signature: known C2 port"
		}
		return Alert{
			RuleID:         "reverse_shell",
			Severity:       "high",
			RiskScore:      85,
			Reason:         reason,
			Recommendation: "validate process tree, isolate pod, capture memory snapshot",
			Event:          evt,
		}, true
	}
	return Alert{}, false
}

func detectInjection(evt RuntimeEvent) (Alert, bool) {
	et := toString(evt.EventType[:])
	if et == "ptrace" || et == "mmap_exec" || et == "memfd" {
		return Alert{
			RuleID:         "process_injection",
			Severity:       "high",
			RiskScore:      90,
			Reason:         "injection primitive observed (ptrace/mmap_exec/memfd)",
			Recommendation: "freeze process, capture core, verify container origin",
			Event:          evt,
		}, true
	}
	return Alert{}, false
}

func detectSuspiciousExec(evt RuntimeEvent) (Alert, bool) {
	et := toString(evt.EventType[:])
	if et != "exec" {
		return Alert{}, false
	}

	binPath := sanitizePath(toString(evt.Filename[:]))
	comm := toString(evt.Comm[:])

	inTmp := strings.HasPrefix(binPath, "/tmp")
	memfd := strings.Contains(binPath, "memfd")
	unusualParent := evt.PPID == 1 && evt.UID != 0 // orphaned non-root process

	if inTmp || memfd || unusualParent {
		reason := "suspicious execution path"
		switch {
		case inTmp:
			reason = "binary executed from /tmp"
		case memfd:
			reason = "anonymous memfd execution"
		case unusualParent:
			reason = "unexpected parent-child relationship"
		}

		return Alert{
			RuleID:         "suspicious_exec",
			Severity:       "medium",
			RiskScore:      60,
			Reason:         reason,
			Recommendation: "trace process lineage and compare against allowed list",
			Event:          evt,
		}, true
	}

	// If we see connect with shell binary but different port, treat as medium.
	if toString(evt.EventType[:]) == "connect" {
		port := ntohs(evt.DstPort)
		_, binFlag := reverseShellBins[comm]
		if binFlag && port != 0 {
			return Alert{
				RuleID:         "shell_network_activity",
				Severity:       "medium",
				RiskScore:      55,
				Reason:         "shell binary initiated network connection",
				Recommendation: "verify if session is expected (kubectl exec vs unknown)",
				Event:          evt,
			}, true
		}
	}

	return Alert{}, false
}

func toString(buf []byte) string {
	n := bytes.IndexByte(buf, 0)
	if n == -1 {
		n = len(buf)
	}
	return string(buf[:n])
}

func sanitizePath(p string) string {
	// Keep it simple; trim trailing nulls/spaces.
	return strings.TrimSpace(p)
}
