package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ContainerMeta holds lightweight container data.
type ContainerMeta struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Runtime string `json:"runtime"`
}

// PodMeta represents Kubernetes metadata when available.
type PodMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Node      string `json:"node"`
}

var idRegex = regexp.MustCompile(`[0-9a-f]{32,64}`)

// LookupContainerMetadata parses /proc/<pid>/cgroup for container IDs.
func LookupContainerMetadata(pid int, cgroupID uint64) ContainerMeta {
	path := filepath.Join("/proc", strconv.Itoa(pid), "cgroup")
	f, err := os.Open(path)
	if err != nil {
		return ContainerMeta{ID: "host", Name: "", Runtime: ""}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := idRegex.FindString(line); m != "" {
			return ContainerMeta{ID: m, Name: m[:12], Runtime: "cgroup"}
		}
	}
	if err := scanner.Err(); err != nil {
		return ContainerMeta{ID: "error", Name: "error", Runtime: "cgroup"}
	}

	return ContainerMeta{ID: "cgid", Name: "cgid", Runtime: "cgroup"}
}

// LookupPodMeta derives pod info from env or hostname for demo purposes.
func LookupPodMeta() PodMeta {
	ns := getenv("POD_NAMESPACE", "default")
	name := getenv("POD_NAME", hostnameFallback())
	node := getenv("NODE_NAME", "node-unknown")
	return PodMeta{Name: name, Namespace: ns, Node: node}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hostnameFallback() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return strings.ReplaceAll(h, "\n", "")
}
