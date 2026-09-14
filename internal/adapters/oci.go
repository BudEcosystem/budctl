package adapters

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// OCI talks the registry v2 API. It requests manifests only — never a blob.
// FRD-020 D3: access and connectivity are provable from metadata, and pulling
// layers would fill the very disk nodes.imagefs is trying to measure.
type OCI struct {
	net *Net
}

func NewOCI(n *Net) *OCI { return &OCI{net: n} }

// ManifestStatus is the outcome of resolving one image reference.
type ManifestStatus string

const (
	ManifestOK           ManifestStatus = "ok"
	ManifestNotFound     ManifestStatus = "notfound"
	ManifestUnauthorized ManifestStatus = "unauthorized"
	ManifestUnreachable  ManifestStatus = "unreachable"
)

const acceptManifests = "application/vnd.oci.image.index.v1+json," +
	"application/vnd.oci.image.manifest.v1+json," +
	"application/vnd.docker.distribution.manifest.list.v2+json," +
	"application/vnd.docker.distribution.manifest.v2+json"

// Reachable answers the default registry question: does /v2/ respond at all?
// A 401 is a PASS — it proves DNS, routing, TLS and a live registry, which is
// the whole question before credentials have been issued (FRD-020 D7).
func (o *OCI) Reachable(ctx context.Context, host string) HTTPResult {
	return o.net.Probe(ctx, "https://"+apiHost(host)+"/v2/")
}

// Manifest resolves registry/repository:reference using credentials when they
// are supplied, following the token flow when the registry asks for one.
func (o *OCI) Manifest(ctx context.Context, registry, repo, ref string, cred *Credential) (ManifestStatus, string) {
	u := fmt.Sprintf("https://%s/v2/%s/manifests/%s", apiHost(registry), repo, ref)

	do := func(auth string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", acceptManifests)
		req.Header.Set("User-Agent", "budctl/1.0")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		return o.net.Client.Do(req)
	}

	resp, err := do("")
	if err != nil {
		return ManifestUnreachable, cleanErr(err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Header lookup must be case-insensitive: HTTP/2 lowercases header
		// names, and a case-sensitive map read here reports every anonymous
		// Docker Hub pull as "unauthorized".
		challenge := resp.Header.Get("WWW-Authenticate")
		if tok, terr := o.token(ctx, challenge, repo, cred); terr == nil && tok != "" {
			if resp, err = do("Bearer " + tok); err != nil {
				return ManifestUnreachable, cleanErr(err)
			}
			_ = resp.Body.Close()
		} else if cred != nil {
			basic := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
			if resp, err = do("Basic " + basic); err != nil {
				return ManifestUnreachable, cleanErr(err)
			}
			_ = resp.Body.Close()
		}
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return ManifestOK, "manifest resolved"
	case resp.StatusCode == http.StatusNotFound:
		return ManifestNotFound, "registry answered but the tag does not exist"
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ManifestUnauthorized, fmt.Sprintf("HTTP %d: credentials missing or rejected", resp.StatusCode)
	default:
		return ManifestUnreachable, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
}

var challengeRE = regexp.MustCompile(`realm="([^"]+)".*?service="([^"]+)"`)

func (o *OCI) token(ctx context.Context, challenge, repo string, cred *Credential) (string, error) {
	m := challengeRE.FindStringSubmatch(challenge)
	if m == nil {
		return "", fmt.Errorf("no bearer challenge")
	}
	u := fmt.Sprintf("%s?service=%s&scope=repository:%s:pull", m[1], url.QueryEscape(m[2]), repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "budctl/1.0")
	if cred != nil {
		req.SetBasicAuth(cred.Username, cred.Password)
	}
	resp, err := o.net.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload.Token != "" {
		return payload.Token, nil
	}
	return payload.AccessToken, nil
}

// ImageRef splits an image reference into registry, repository and reference,
// applying Docker Hub's implicit library/ prefix.
func ImageRef(image string) (registry, repo, ref string) {
	registry = "docker.io"
	rest := image
	if i := strings.Index(image, "/"); i >= 0 {
		first := image[:i]
		if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
			registry, rest = first, image[i+1:]
		}
	}
	ref = "latest"
	if at := strings.Index(rest, "@"); at >= 0 {
		repo, ref = rest[:at], rest[at+1:]
	} else if colon := strings.LastIndex(rest, ":"); colon >= 0 && !strings.Contains(rest[colon:], "/") {
		repo, ref = rest[:colon], rest[colon+1:]
	} else {
		repo = rest
	}
	if registry == "docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	return registry, repo, ref
}

// RegistryOf returns just the registry host for an image reference.
func RegistryOf(image string) string {
	r, _, _ := ImageRef(image)
	return r
}

func apiHost(host string) string {
	if host == "docker.io" {
		return "registry-1.docker.io"
	}
	return host
}

// ChartManifest resolves an OCI Helm chart without downloading the archive.
func (o *OCI) ChartManifest(ctx context.Context, ref, version string, cred *Credential) (ManifestStatus, string) {
	ref = strings.TrimPrefix(ref, "oci://")
	host, repo, _ := strings.Cut(ref, "/")
	return o.Manifest(ctx, host, repo, version, cred)
}

// ServerClock returns the registry's Date header, a convenient reference clock
// that needs no extra dependency.
func (o *OCI) ServerClock(ctx context.Context, host string) (time.Time, bool) {
	r := o.Reachable(ctx, host)
	return r.ServerTime, !r.ServerTime.IsZero()
}
