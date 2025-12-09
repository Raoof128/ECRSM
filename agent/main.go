package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// Event mirrors ebpf/event_t (packed little-endian).
type Event struct {
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	CgroupID  uint64
	DstIP     uint32
	DstPort   uint16
	Proto     uint8
	_         uint8 // padding to align to 2 bytes
	Comm      [16]byte
	Filename  [256]byte
	EventType [16]byte
}

// RuntimeEvent is the enriched representation consumed by the rules engine.
type RuntimeEvent struct {
	Event
	Container ContainerMeta `json:"container"`
	Pod       PodMeta       `json:"pod"`
	Timestamp time.Time     `json:"timestamp"`
	Addr      string        `json:"addr"`
}

// AgentConfig holds basic runtime parameters.
type AgentConfig struct {
	BPFObjectPath string
	ListenAddr    string
}

func main() {
	logger := log.New(os.Stdout, "agent ", log.LstdFlags|log.LUTC)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := AgentConfig{
		BPFObjectPath: envOr("BPF_OBJECT", "../ebpf/process_monitor.bpf.o"),
		ListenAddr:    envOr("LISTEN_ADDR", ":8090"),
	}

	spec, err := ebpf.LoadCollectionSpec(cfg.BPFObjectPath)
	if err != nil {
		logger.Fatalf("load bpf spec: %v", err)
	}

	var objs struct {
		Events *ebpf.Map `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		logger.Fatalf("load/assign objs: %v", err)
	}
	defer objs.Events.Close()

	reader, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		logger.Fatalf("perf reader: %v", err)
	}
	defer reader.Close()

	alertCh := make(chan Alert, 1024)
	defer close(alertCh)
	srv := NewAlertServer(cfg.ListenAddr, logger)
	go func() {
		if err := srv.ListenAndServe(ctx, alertCh); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("http server stopped: %v", err)
		}
	}()

	logger.Println("runtime monitor started; listening for kernel events")

	for {
		select {
		case <-ctx.Done():
			logger.Println("shutting down")
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if perf.IsUnknownEvent(err) || errors.Is(err, perf.ErrClosed) {
				continue
			}
			logger.Printf("read perf event: %v", err)
			continue
		}

		if record.LostSamples > 0 {
			logger.Printf("warning: lost %d samples", record.LostSamples)
		}

		var evt Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
			logger.Printf("parse event: %v", err)
			continue
		}

		enriched := enrich(evt)
		alerts := EvaluateRules(enriched)
		for _, alert := range alerts {
			payload, _ := json.Marshal(alert)
			logger.Println(string(payload))
			select {
			case alertCh <- alert:
			default:
				logger.Printf("alert channel full, dropping alert: %s", alert.RuleID)
			}
		}
	}
}

func enrich(evt Event) RuntimeEvent {
	pid := int(evt.PID)
	container := LookupContainerMetadata(pid, evt.CgroupID)
	pod := LookupPodMeta()

	addr := ""
	if evt.DstIP != 0 {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, evt.DstIP)
		addr = net.JoinHostPort(ip.String(), fmtPort(evt.DstPort))
	}

	return RuntimeEvent{
		Event:     evt,
		Container: container,
		Pod:       pod,
		Timestamp: time.Now().UTC(),
		Addr:      addr,
	}
}

func fmtPort(p uint16) string {
	if p == 0 {
		return ""
	}
	return strconv.Itoa(int(ntohs(p)))
}

func ntohs(n uint16) uint16 {
	return (n>>8 | n<<8)
}

// envOr returns environment value or default.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
