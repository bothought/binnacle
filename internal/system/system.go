// Package system collects a lightweight snapshot of the host.
package system

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/sensors"
)

type Disk struct {
	Mount   string
	FSType  string
	Total   uint64
	Used    uint64
	Percent float64
}

type Temp struct {
	Sensor  string
	Celsius float64
}

type Snapshot struct {
	At             time.Time
	Hostname       string
	OS             string
	Platform       string
	Kernel         string
	Uptime         uint64
	CPUModel       string
	CPUCores       int
	CPUPercent     float64
	Load1          float64
	Load5          float64
	Load15         float64
	MemTotal       uint64
	MemUsed        uint64
	MemPercent     float64
	SwapTotal      uint64
	SwapUsed       uint64
	SwapPercent    float64
	Disks          []Disk
	NetRx          float64
	NetTx          float64
	Temps          []Temp
	FailedUnits    []string
	OSImageVersion string
	StagedVersion  string
}

type Point struct {
	At   time.Time
	CPU  float64
	Mem  float64
	Disk float64
	Rx   float64
	Tx   float64
}

type Collector struct {
	mu       sync.RWMutex
	latest   Snapshot
	history  []Point
	lastRx   uint64
	lastTx   uint64
	lastAt   time.Time
	maxPoint int
}

func New() *Collector {
	c := &Collector{maxPoint: 720}
	// Prime the CPU percentage baseline.
	_, _ = cpu.Percent(0, false)
	return c
}

func (c *Collector) Latest() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest
}

func (c *Collector) History() []Point {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Point, len(c.history))
	copy(out, c.history)
	return out
}

func (c *Collector) Collect(ctx context.Context) Snapshot {
	var s Snapshot
	s.At = time.Now()

	if hi, err := host.InfoWithContext(ctx); err == nil {
		s.Hostname = hi.Hostname
		s.Platform = hi.Platform
		s.OS = strings.TrimSpace(hi.Platform + " " + hi.PlatformVersion)
		s.Kernel = hi.KernelVersion
		s.Uptime = hi.Uptime
	}
	if s.Hostname == "" {
		s.Hostname, _ = os.Hostname()
	}
	if infos, err := cpu.InfoWithContext(ctx); err == nil && len(infos) > 0 {
		s.CPUModel = strings.TrimSpace(infos[0].ModelName)
		s.CPUCores = int(infos[0].Cores)
		if s.CPUCores == 0 {
			s.CPUCores = len(infos)
		}
	}
	if pct, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(pct) > 0 {
		s.CPUPercent = clamp(pct[0], 0, 100)
	}
	if v, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		s.MemTotal, s.MemUsed, s.MemPercent = v.Total, v.Used, v.UsedPercent
	}
	if v, err := mem.SwapMemoryWithContext(ctx); err == nil {
		s.SwapTotal, s.SwapUsed, s.SwapPercent = v.Total, v.Used, v.UsedPercent
	}
	if v, err := load.AvgWithContext(ctx); err == nil {
		s.Load1, s.Load5, s.Load15 = v.Load1, v.Load5, v.Load15
	}
	s.Disks = disks(ctx)
	s.Temps = temperatures(ctx)
	s.FailedUnits = failedUnits(ctx)
	s.OSImageVersion, s.StagedVersion = ostreeVersions(ctx)
	s.NetRx, s.NetTx, c.lastRx, c.lastTx, c.lastAt = netRate(ctx, c.lastRx, c.lastTx, c.lastAt)

	c.mu.Lock()
	c.latest = s
	p := Point{At: s.At, CPU: s.CPUPercent, Mem: s.MemPercent, Disk: maxDisk(s.Disks), Rx: s.NetRx, Tx: s.NetTx}
	c.history = append(c.history, p)
	if len(c.history) > c.maxPoint {
		c.history = c.history[len(c.history)-c.maxPoint:]
	}
	c.mu.Unlock()
	return s
}

func disks(ctx context.Context) []Disk {
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return nil
	}
	skipFS := map[string]bool{
		"tmpfs": true, "devtmpfs": true, "overlay": true, "squashfs": true,
		"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true,
		"devpts": true, "mqueue": true, "debugfs": true, "tracefs": true,
		"securityfs": true, "pstore": true, "bpf": true, "autofs": true,
		"fusectl": true, "configfs": true, "ramfs": true, "hugetlbfs": true,
		"nsfs": true, "efivarfs": true, "fuse.portal": true,
	}
	skipMount := []string{"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containers/storage/overlay"}
	var out []Disk
	seen := map[string]bool{}
	for _, p := range parts {
		if skipFS[p.Fstype] || seen[p.Mountpoint] {
			continue
		}
		skip := false
		for _, prefix := range skipMount {
			if p.Mountpoint == prefix || strings.HasPrefix(p.Mountpoint, prefix+"/") {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		u, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil || u.Total == 0 {
			continue
		}
		seen[p.Mountpoint] = true
		out = append(out, Disk{Mount: p.Mountpoint, FSType: p.Fstype, Total: u.Total, Used: u.Used, Percent: u.UsedPercent})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Mount == "/" {
			return true
		}
		if out[j].Mount == "/" {
			return false
		}
		return out[i].Mount < out[j].Mount
	})
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

func temperatures(ctx context.Context) []Temp {
	list, err := sensors.TemperaturesWithContext(ctx)
	if err != nil {
		return nil
	}
	var out []Temp
	for _, t := range list {
		if t.Temperature <= 0 || t.Temperature > 150 {
			continue
		}
		name := t.SensorKey
		if name == "" {
			continue
		}
		out = append(out, Temp{Sensor: name, Celsius: t.Temperature})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sensor < out[j].Sensor })
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

func failedUnits(ctx context.Context) []string {
	seen := map[string]bool{}
	var out []string
	for _, args := range [][]string{
		{"--failed", "--no-legend", "--plain", "--no-pager"},
		{"--user", "--failed", "--no-legend", "--plain", "--no-pager"},
	} {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		cmd := exec.CommandContext(c, "systemctl", args...)
		b, err := cmd.Output()
		cancel()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			name := strings.TrimPrefix(f[0], "●")
			if name == "" || strings.HasPrefix(name, "0 ") || strings.Contains(line, "loaded units listed") {
				continue
			}
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

type ostreeStatus struct {
	Deployments []struct {
		Booted                  bool   `json:"booted"`
		Staged                  bool   `json:"staged"`
		Version                 string `json:"version"`
		ContainerImageReference string `json:"container-image-reference"`
	} `json:"deployments"`
}

func ostreeVersions(ctx context.Context) (booted, staged string) {
	if _, err := exec.LookPath("rpm-ostree"); err != nil {
		return "", ""
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(c, "rpm-ostree", "status", "--json").Output()
	if err != nil {
		return "", ""
	}
	var st ostreeStatus
	if json.Unmarshal(b, &st) != nil {
		return "", ""
	}
	for _, d := range st.Deployments {
		if d.Booted {
			booted = d.Version
		}
		if d.Staged {
			staged = d.Version
		}
	}
	return booted, staged
}

func netRate(ctx context.Context, lastRx, lastTx uint64, lastAt time.Time) (rx, tx float64, totalRx, totalTx uint64, at time.Time) {
	counters, err := gnet.IOCountersWithContext(ctx, true)
	if err != nil {
		return 0, 0, lastRx, lastTx, lastAt
	}
	for _, c := range counters {
		if c.Name == "lo" {
			continue
		}
		totalRx += c.BytesRecv
		totalTx += c.BytesSent
	}
	at = time.Now()
	if lastAt.IsZero() || totalRx < lastRx || totalTx < lastTx {
		return 0, 0, totalRx, totalTx, at
	}
	secs := at.Sub(lastAt).Seconds()
	if secs <= 0 {
		return 0, 0, totalRx, totalTx, at
	}
	rx = float64(totalRx-lastRx) / secs
	tx = float64(totalTx-lastTx) / secs
	return rx, tx, totalRx, totalTx, at
}

func maxDisk(ds []Disk) float64 {
	var max float64
	for _, d := range ds {
		if d.Percent > max {
			max = d.Percent
		}
	}
	return max
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
