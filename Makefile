.PHONY: all bpf agent dashboard test lint fmt clean

BPF_OBJ=ebpf/process_monitor.bpf.o

all: bpf agent dashboard

bpf:
	cd ebpf && clang -O2 -g -target bpf -c process_monitor.c -o process_monitor.bpf.o

agent:
	cd agent && go build ./...

dashboard:
	cd dashboard && npm install && npm run build

fmt:
	gofmt -w agent/*.go

lint: fmt
	cd dashboard && npm run lint

test:
	cd agent && go test ./...

clean:
	rm -f $(BPF_OBJ)
