package tests

import (
    "testing"

    monitor "github.com/educational/ebpf-runtime-monitor/agent"
)

// helper to create byte arrays for strings
func b16(s string) [16]byte {
    var out [16]byte
    copy(out[:], []byte(s))
    return out
}

func b256(s string) [256]byte {
    var out [256]byte
    copy(out[:], []byte(s))
    return out
}

func TestReverseShellRule(t *testing.T) {
    evt := monitor.RuntimeEvent{
        Event: monitor.Event{
            UID:       1000,
            DstPort:   htons(4444),
            EventType: b16("connect"),
            Comm:      b16("bash"),
        },
    }
    alerts := monitor.EvaluateRules(evt)
    if len(alerts) == 0 {
        t.Fatalf("expected reverse shell alert")
    }
}

func TestInjectionRule(t *testing.T) {
    evt := monitor.RuntimeEvent{Event: monitor.Event{EventType: b16("ptrace")}}
    alerts := monitor.EvaluateRules(evt)
    if len(alerts) == 0 || alerts[0].RuleID != "process_injection" {
        t.Fatalf("expected injection alert")
    }
}

func TestSuspiciousExecTmp(t *testing.T) {
    evt := monitor.RuntimeEvent{Event: monitor.Event{
        EventType: b16("exec"),
        Filename:  b256("/tmp/evil"),
    }}
    alerts := monitor.EvaluateRules(evt)
    if len(alerts) == 0 || alerts[0].RuleID != "suspicious_exec" {
        t.Fatalf("expected suspicious exec alert")
    }
}

func htons(p uint16) uint16 {
    return (p<<8 | p>>8)
}
