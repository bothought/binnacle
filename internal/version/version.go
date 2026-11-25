// Package version implements a tolerant version comparator for self-hosted
// software. It understands semver, CalVer, and common suffixes without
// pretending that every project follows a strict scheme.
package version

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var versionRE = regexp.MustCompile(`(?i)\bv?(\d+(?:[._-]\d+){0,4}(?:[-+][0-9A-Za-z.-]+)?)`)
var securityRE = regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d{3,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|security|vulnerab|exploit)\b`)

// Extract returns the first version-looking token in s.
func Extract(s string) string {
	m := versionRE.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimPrefix(m[1], "v")
}

// Normalize strips a leading v and surrounding whitespace.
func Normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	return s
}

// Compare returns -1, 0 or 1. Unparsable inputs are compared as normalized
// strings, so equality still works and we never claim an update we cannot
// substantiate.
func Compare(a, b string) int {
	a, b = Normalize(a), Normalize(b)
	as, bs := split(a), split(b)
	if len(as) == 0 || len(bs) == 0 {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	}
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		x, y := as[i], bs[i]
		if x == y {
			continue
		}
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		if xerr == nil && yerr == nil {
			if xn < yn {
				return -1
			}
			return 1
		}
		// A numeric segment sorts after a non-numeric one.
		if xerr == nil && yerr != nil {
			return 1
		}
		if xerr != nil && yerr == nil {
			return -1
		}
		if strings.ToLower(x) < strings.ToLower(y) {
			return -1
		}
		return 1
	}
	if len(as) == len(bs) {
		return 0
	}
	aLong := len(as) > len(bs)
	var extra []string
	if aLong {
		extra = as[len(bs):]
	} else {
		extra = bs[len(as):]
	}
	for _, x := range extra {
		if n, err := strconv.ParseUint(x, 10, 64); err == nil {
			if n != 0 {
				if aLong {
					return 1
				}
				return -1
			}
			continue
		}
		// A trailing alphabetic suffix is a prerelease; the plain release wins.
		if aLong {
			return -1
		}
		return 1
	}
	return 0
}

// Severity describes the size of a version jump.
func Severity(current, latest string) string {
	if current == "" || latest == "" {
		return "unknown"
	}
	if Compare(current, latest) >= 0 {
		return "none"
	}
	a, b := split(Normalize(current)), split(Normalize(latest))
	if len(a) == 0 || len(b) == 0 {
		return "unknown"
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			switch i {
			case 0:
				return "major"
			case 1:
				return "minor"
			default:
				return "patch"
			}
		}
	}
	return "patch"
}

// LooksSecurity reports whether release notes look like a security release.
// This is deliberately a heuristic; callers must show the release link.
func LooksSecurity(notes string) bool {
	return securityRE.MatchString(notes)
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		if unicode.IsDigit(r) || unicode.IsLetter(r) {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}
