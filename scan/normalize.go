package scan

import (
	"net/url"
	"strings"
)

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func upper(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// originOf returns scheme://host[:port] for an http(s) URL, or "" when the input
// is not one. Services are hosts, not paths: a scanner that reports a matched URL
// with a payload in the query would otherwise create a new "service" per payload.
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// NormalizeSeverity maps any scanner's severity vocabulary onto the four levels
// the findings table accepts. Anything unrecognized becomes "" so the UI shows it
// as unclassified rather than inventing a rank.
func NormalizeSeverity(s string) string {
	switch lower(s) {
	case "critical", "fatal":
		return "critical"
	case "high", "error":
		return "high"
	case "medium", "moderate", "warn", "warning":
		return "medium"
	case "low", "note", "info", "informational":
		return "low"
	}
	return ""
}

// CleanID turns a scanner's identifier into a stable machine key: no spaces, no
// case ambiguity. Used for VulnClass and ExternalID so fingerprints survive.
func CleanID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "-")
	return s
}

// isEndpointURL reports whether an http(s) URL addresses something below the site
// root (a path other than "/", or a query), i.e. an endpoint rather than a service.
func isEndpointURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	return (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != ""
}

// Clip bounds a field that lands in a database column. Scanners occasionally emit
// megabyte-long matched bodies; the evidence needs the head, not the tail.
func Clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}
