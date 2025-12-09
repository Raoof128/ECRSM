# API / Event Reference

## SSE endpoint
- **URL**: `/events`
- **Method**: GET
- **Protocol**: Server-Sent Events (`text/event-stream`)
- **Payload**: Each message is a JSON-serialized `Alert` preceded by `data: `.

Example stream frame:
```
data: {"rule_id":"reverse_shell","severity":"high","risk_score":85,...}

```

### Health
- `GET /healthz` → `200 OK` with body `ok`.

## Alert schema
```
Alert {
  rule_id: string,
  severity: string,
  risk_score: int,
  reason: string,
  recommendation: string,
  event: RuntimeEvent,
  container: ContainerMeta,
  timestamp: RFC3339 time,
  addr: string
}

RuntimeEvent {
  PID: uint32,
  PPID: uint32,
  UID: uint32,
  GID: uint32,
  CgroupID: uint64,
  DstIP: uint32,
  DstPort: uint16 (network order),
  Proto: uint8,
  Comm: string,
  Filename: string,
  EventType: string
}

ContainerMeta { id, name, runtime }
PodMeta { name, namespace, node }
```

## Environment variables
- `BPF_OBJECT`: path to `process_monitor.bpf.o` (default `../ebpf/process_monitor.bpf.o`).
- `LISTEN_ADDR`: HTTP listen address for SSE server (default `:8090`).
- `POD_NAME`, `POD_NAMESPACE`, `NODE_NAME`: optional pod metadata hints.

## Error handling
- Connections without SSE support receive `500 streaming unsupported`.
- Slow consumers may drop messages if their per-connection buffer fills (non-blocking broadcast to protect agent health).
