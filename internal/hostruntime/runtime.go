// Package hostruntime discovers containers from rootless Podman or Docker.
package hostruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortMapping struct {
	HostIP        string
	HostPort      int
	ContainerPort int
	Proto         string
}

type Container struct {
	ID     string
	Name   string
	Image  string
	Status string
	Unit   string
	Labels map[string]string
	Ports  []PortMapping
}

type Runtime struct {
	mu      sync.Mutex
	cache   []Container
	at      time.Time
	ttl     time.Duration
	runtime string
}

func New() *Runtime {
	r := &Runtime{ttl: 10 * time.Second}
	switch {
	case hasCommand("podman"):
		r.runtime = "podman"
	case hasCommand("docker"):
		r.runtime = "docker"
	}
	return r
}

func (r *Runtime) Kind() string {
	if r == nil {
		return ""
	}
	return r.runtime
}

func (r *Runtime) Containers(ctx context.Context) []Container {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.at) < r.ttl {
		return r.cache
	}
	var out []Container
	switch r.runtime {
	case "podman":
		out = podmanContainers(ctx)
	case "docker":
		out = dockerContainers(ctx)
	}
	r.cache = out
	r.at = time.Now()
	return out
}

func (r *Runtime) FindByImage(image string) []Container {
	all := r.Containers(context.Background())
	var out []Container
	for _, c := range all {
		if sameImage(c.Image, image) {
			out = append(out, c)
		}
	}
	return out
}

type podmanPS struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
	Ports  []struct {
		HostIP        string `json:"HostIP"`
		HostPort      int    `json:"HostPort"`
		ContainerPort int    `json:"ContainerPort"`
		Protocol      string `json:"Protocol"`
	} `json:"Ports"`
}

func podmanContainers(ctx context.Context) []Container {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(c, "podman", "ps", "--format", "json").Output()
	if err != nil {
		return nil
	}
	var rows []podmanPS
	if json.Unmarshal(b, &rows) != nil {
		return nil
	}
	out := make([]Container, 0, len(rows))
	for _, row := range rows {
		name := ""
		if len(row.Names) > 0 {
			name = row.Names[0]
		}
		unit := row.Labels["PODMAN_SYSTEMD_UNIT"]
		if unit == "" {
			unit = row.Labels["com.docker.compose.project"]
		}
		ct := Container{ID: row.ID, Name: name, Image: row.Image, Status: row.Status, Unit: unit, Labels: row.Labels}
		for _, p := range row.Ports {
			if p.HostPort == 0 {
				continue
			}
			ct.Ports = append(ct.Ports, PortMapping{HostIP: p.HostIP, HostPort: p.HostPort, ContainerPort: p.ContainerPort, Proto: strings.ToLower(p.Protocol)})
		}
		out = append(out, ct)
	}
	return out
}

type dockerPS struct {
	ID     string `json:"ID"`
	Names  string `json:"Names"`
	Image  string `json:"Image"`
	State  string `json:"State"`
	Status string `json:"Status"`
	Labels string `json:"Labels"`
	Ports  string `json:"Ports"`
}

func dockerContainers(ctx context.Context) []Container {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, "docker", "ps", "--format", "{{json .}}")
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil
	}
	var out []Container
	sc := bufio.NewScanner(outPipe)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var row dockerPS
		if json.Unmarshal(sc.Bytes(), &row) != nil {
			continue
		}
		ct := Container{ID: row.ID, Name: row.Names, Image: row.Image, Status: row.Status, Labels: parseLabels(row.Labels)}
		ct.Unit = ct.Labels["PODMAN_SYSTEMD_UNIT"]
		if ct.Unit == "" {
			ct.Unit = ct.Labels["com.docker.compose.project"]
		}
		ct.Ports = parseDockerPorts(row.Ports)
		out = append(out, ct)
	}
	_ = cmd.Wait()
	return out
}

func parseLabels(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if ok {
			out[strings.TrimSpace(k)] = v
		}
	}
	return out
}

// parseDockerPorts handles strings such as
// "127.0.0.1:8091->8091/tcp, 0.0.0.0:80->80/tcp, 443/udp".
func parseDockerPorts(s string) []PortMapping {
	var out []PortMapping
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" || !strings.Contains(item, "->") {
			continue
		}
		left, right, _ := strings.Cut(item, "->")
		proto := "tcp"
		if p, rest, ok := strings.Cut(right, "/"); ok {
			right = p
			proto = strings.ToLower(rest)
		}
		hostIP, hostPortStr := "", ""
		if strings.Contains(left, ":") {
			idx := strings.LastIndex(left, ":")
			hostIP, hostPortStr = left[:idx], left[idx+1:]
		} else {
			hostPortStr = left
		}
		hostPort, err := strconv.Atoi(hostPortStr)
		if err != nil || hostPort == 0 {
			continue
		}
		cport, _ := strconv.Atoi(right)
		out = append(out, PortMapping{HostIP: strings.Trim(hostIP, "[]"), HostPort: hostPort, ContainerPort: cport, Proto: proto})
	}
	return out
}

func hasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func sameImage(a, b string) bool {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		if i := strings.Index(s, "@"); i >= 0 {
			s = s[:i]
		}
		if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
			s = s[:i]
		}
		s = strings.TrimPrefix(s, "docker.io/library/")
		s = strings.TrimPrefix(s, "docker.io/")
		s = strings.TrimPrefix(s, "index.docker.io/")
		return s
	}
	return norm(a) == norm(b)
}
