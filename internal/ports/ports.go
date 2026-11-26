// Package ports turns listening sockets into stable service records.
package ports

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/hostruntime"
	"github.com/bothought/binnacle/internal/store"
)

type Socket struct {
	Proto   string
	Port    int
	Bind    string
	PID     int
	Process string
}

type Collector struct {
	cfg     config.CollectorConfig
	runtime *hostruntime.Runtime
}

func New(cfg config.CollectorConfig, rt *hostruntime.Runtime) *Collector {
	return &Collector{cfg: cfg, runtime: rt}
}

func (c *Collector) Scan(ctx context.Context) ([]store.Service, error) {
	sockets, err := scanSockets(ctx)
	if err != nil {
		return nil, err
	}
	containers := c.runtime.Containers(ctx)
	return buildServices(sockets, containers, c.cfg.IgnorePatterns), nil
}

func (c *Collector) Runtime() *hostruntime.Runtime { return c.runtime }

func scanSockets(ctx context.Context) ([]Socket, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "ss", "-H", "-l", "-t", "-u", "-n", "-p").Output()
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	return ParseSS(string(out)), nil
}

var pidRE = regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)

// ParseSS parses the output of `ss -H -ltunp`.
func ParseSS(output string) []Socket {
	seen := map[string]bool{}
	var out []Socket
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := strings.ToLower(f[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		state := strings.ToUpper(f[1])
		if proto == "tcp" && state != "LISTEN" {
			continue
		}
		host, portStr, ok := splitAddr(f[4])
		if !ok {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 {
			continue
		}
		var pid int
		var process string
		if len(f) > 6 {
			rest := strings.Join(f[6:], " ")
			if m := pidRE.FindStringSubmatch(rest); len(m) == 3 {
				process = m[1]
				pid, _ = strconv.Atoi(m[2])
			}
		}
		key := fmt.Sprintf("%s|%s|%d|%d", proto, host, port, pid)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Socket{Proto: proto, Port: port, Bind: host, PID: pid, Process: process})
	}
	return out
}

func splitAddr(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.LastIndex(s, "]")
		if end < 0 || end+2 > len(s) || s[end+1] != ':' {
			return "", "", false
		}
		host = s[1:end]
		if i := strings.Index(host, "%"); i >= 0 {
			host = host[:i]
		}
		return host, s[end+2:], true
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", "", false
	}
	host = s[:idx]
	if i := strings.Index(host, "%"); i >= 0 {
		host = host[:i]
	}
	if host == "*" || host == "" {
		host = "0.0.0.0"
	}
	return host, s[idx+1:], true
}

func buildServices(sockets []Socket, containers []hostruntime.Container, ignores []string) []store.Service {
	byPort := map[string]*hostruntime.Container{}
	byUnit := map[string]*hostruntime.Container{}
	byName := map[string]*hostruntime.Container{}
	for i := range containers {
		ct := &containers[i]
		for _, p := range ct.Ports {
			key := fmt.Sprintf("%s:%d", p.Proto, p.HostPort)
			if _, ok := byPort[key]; !ok {
				byPort[key] = ct
			}
		}
		if ct.Unit != "" {
			byUnit[ct.Unit] = ct
			byUnit[strings.TrimSuffix(ct.Unit, ".service")] = ct
		}
		byName[ct.Name] = ct
	}

	services := map[string]*store.Service{}
	for _, s := range sockets {
		exe, unit := processInfo(s.PID)
		ct := byPort[s.Proto+":"+strconv.Itoa(s.Port)]
		if ct == nil && unit != "" {
			ct = byUnit[unit]
		}
		if ct == nil && s.Process != "" {
			ct = byName[s.Process]
		}
		key, name, kind := "", "", ""
		var svc *store.Service
		switch {
		case ct != nil:
			key = "container:" + ct.Name
			name = strings.TrimPrefix(ct.Name, "systemd-")
			kind = "container"
		case unit != "":
			key = "unit:" + unit
			name = strings.TrimSuffix(unit, ".service")
			kind = "systemd"
		case exe != "":
			key = "proc:" + exe
			name = exe
			kind = "process"
		default:
			key = fmt.Sprintf("port:%s:%d", s.Proto, s.Port)
			name = fmt.Sprintf(":%d", s.Port)
			kind = "socket"
		}
		if svc = services[key]; svc == nil {
			svc = &store.Service{Key: key, Name: name, Kind: kind, Unit: unit, Ports: nil, Exposure: "loopback", Visibility: "auto"}
			if ct != nil {
				svc.Unit = ct.Unit
				svc.Container = ct.Name
				svc.Image = ct.Image
			}
			services[key] = svc
		}
		exposure := exposureOf(s.Bind)
		if exposureRank(exposure) > exposureRank(svc.Exposure) {
			svc.Exposure = exposure
		}
		if !containsPort(svc.Ports, s) {
			svc.Ports = append(svc.Ports, store.Port{Proto: s.Proto, Port: s.Port, Bind: s.Bind})
		}
		_ = exe
	}

	out := make([]store.Service, 0, len(services))
	for _, sv := range services {
		sort.Slice(sv.Ports, func(i, j int) bool {
			if sv.Ports[i].Port != sv.Ports[j].Port {
				return sv.Ports[i].Port < sv.Ports[j].Port
			}
			return sv.Ports[i].Proto < sv.Ports[j].Proto
		})
		sv.Ignored = matchesAny(ignores, sv.Name, sv.Unit, sv.Container, sv.Image)
		if !sv.Ignored && sv.Kind == "socket" && allEphemeral(sv.Ports) {
			// Unattributed high ports are usually desktop app churn. Keep them
			// in the inventory, but out of the default view and alerts.
			sv.Ignored = true
		}
		out = append(out, *sv)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExposureRank() != out[j].ExposureRank() {
			return out[i].ExposureRank() > out[j].ExposureRank()
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func processInfo(pid int) (exe, unit string) {
	if pid <= 0 {
		return "", ""
	}
	if p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		exe = path.Base(strings.TrimSuffix(p, " (deleted)"))
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return exe, ""
	}
	unitRE := regexp.MustCompile(`([A-Za-z0-9_.@-]+\.service)`)
	for _, line := range strings.Split(string(b), "\n") {
		// A cgroup path can contain the user manager (user@1000.service)
		// and the actual unit (systemd-caddy.service). The deepest service
		// is the owner we want.
		matches := unitRE.FindAllStringSubmatch(line, -1)
		if len(matches) == 0 {
			continue
		}
		unit := matches[len(matches)-1][1]
		if strings.HasPrefix(unit, "user@") && len(matches) > 1 {
			unit = matches[len(matches)-2][1]
		}
		if strings.HasPrefix(unit, "user@") {
			return exe, ""
		}
		return exe, unit
	}
	return exe, ""
}

func exposureOf(bind string) string {
	ip := net.ParseIP(strings.Trim(bind, "[]"))
	if ip == nil {
		return "lan"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsUnspecified() {
		return "lan"
	}
	if isTailscale(ip) {
		return "tailnet"
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "lan"
	}
	return "public"
}

func isTailscale(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

func exposureRank(s string) int {
	switch s {
	case "public":
		return 4
	case "tailnet":
		return 3
	case "lan":
		return 2
	case "loopback":
		return 1
	}
	return 0
}

func allEphemeral(ports []store.Port) bool {
	if len(ports) == 0 {
		return false
	}
	for _, p := range ports {
		if p.Port < 32768 {
			return false
		}
	}
	return true
}

func containsPort(list []store.Port, s Socket) bool {
	for _, p := range list {
		if p.Proto == s.Proto && p.Port == s.Port && p.Bind == s.Bind {
			return true
		}
	}
	return false
}

func matchesAny(patterns []string, values ...string) bool {
	for _, v := range values {
		if v == "" {
			continue
		}
		v = strings.ToLower(v)
		for _, p := range patterns {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if ok, _ := path.Match(p, v); ok {
				return true
			}
			if !strings.ContainsAny(p, "*?[") && strings.Contains(v, p) {
				return true
			}
		}
	}
	return false
}
