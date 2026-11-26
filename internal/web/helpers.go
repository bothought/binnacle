package web

import (
	"fmt"
	"html/template"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/bothought/binnacle/internal/store"
	"github.com/bothought/binnacle/internal/system"
)

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for n/div >= unit && exp < 5 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanRate(n float64) string {
	if n < 1024 {
		return fmt.Sprintf("%.0f B/s", n)
	}
	units := []string{"KiB/s", "MiB/s", "GiB/s"}
	v := n
	for _, u := range units {
		v /= 1024
		if v < 1024 {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%.1f TiB/s", v/1024)
}

func uptimeText(secs uint64) string {
	d := time.Duration(secs) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

func agoText(unix int64) string {
	if unix <= 0 {
		return "never"
	}
	d := time.Since(time.Unix(unix, 0))
	if d < 0 {
		return "just now"
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func datetimeText(unix int64) string {
	if unix <= 0 {
		return "—"
	}
	return time.Unix(unix, 0).Format("2006-01-02 15:04")
}

func portText(ports []store.Port) string {
	if len(ports) == 0 {
		return "—"
	}
	sort.SliceStable(ports, func(i, j int) bool {
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}
		return ports[i].Proto < ports[j].Proto
	})
	parts := make([]string, 0, len(ports))
	seen := map[string]bool{}
	for _, p := range ports {
		k := fmt.Sprintf("%s/%d", p.Proto, p.Port)
		if seen[k] {
			continue
		}
		seen[k] = true
		parts = append(parts, k)
	}
	return strings.Join(parts, " · ")
}

func exposureText(s string) string {
	switch s {
	case "loopback":
		return "local"
	case "lan":
		return "LAN"
	case "tailnet":
		return "tailnet"
	case "public":
		return "public"
	}
	return s
}

func visibilityText(s string) string {
	switch s {
	case "auto":
		return "auto"
	case "public":
		return "public"
	case "internal":
		return "internal"
	case "hidden":
		return "hidden"
	}
	return s
}

func severityText(s string) string {
	switch s {
	case "security":
		return "security"
	case "image":
		return "image"
	case "update":
		return "update"
	case "unknown":
		return "unknown"
	}
	return s
}

func statusText(s string) string {
	switch s {
	case "ok":
		return "OK"
	case "warn":
		return "warn"
	case "down":
		return "down"
	case "unknown":
		return "unknown"
	}
	return s
}

func statusClass(s string) string {
	switch s {
	case "ok":
		return "ok"
	case "warn":
		return "warn"
	case "down":
		return "down"
	default:
		return "muted"
	}
}

func shortText(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func sparkline(points []system.Point, metric string) template.HTML {
	if len(points) < 2 {
		return template.HTML(`<svg class="spark" viewBox="0 0 100 24" preserveAspectRatio="none"></svg>`)
	}
	vals := make([]float64, 0, len(points))
	for _, p := range points {
		switch metric {
		case "cpu":
			vals = append(vals, p.CPU)
		case "mem":
			vals = append(vals, p.Mem)
		case "disk":
			vals = append(vals, p.Disk)
		case "net":
			vals = append(vals, p.Rx+p.Tx)
		}
	}
	if len(vals) < 2 {
		return template.HTML(`<svg class="spark" viewBox="0 0 100 24" preserveAspectRatio="none"></svg>`)
	}
	min, max := vals[0], vals[0]
	for _, v := range vals {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	if max-min < 1 {
		max = min + 1
	}
	const w, h = 100.0, 24.0
	var b strings.Builder
	b.WriteString(`<svg class="spark" viewBox="0 0 100 24" preserveAspectRatio="none"><polyline points="`)
	for i, v := range vals {
		x := float64(i) / float64(len(vals)-1) * w
		y := h - (v-min)/(max-min)*h
		if math.IsNaN(y) || math.IsInf(y, 0) {
			y = h
		}
		fmt.Fprintf(&b, "%.1f,%.1f ", x, y)
	}
	b.WriteString(`"></polyline></svg>`)
	return template.HTML(b.String())
}
