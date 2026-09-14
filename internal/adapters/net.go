package adapters

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Net performs the off-cluster probes: HTTP, TLS, DNS and raw TCP.
type Net struct {
	Client  *http.Client
	Timeout time.Duration
	// Roots verifies served certificates. nil means this host's own trust
	// store. An internal CA is a deployment choice rather than a defect, so
	// budctl has to be told about it — it cannot be inferred from a chain that
	// simply does not verify.
	Roots *x509.CertPool
}

// TrustCABundle adds the PEM roots in path to everything this adapter
// verifies, the HTTP client included, so a certificate issued by an internal
// CA can be judged on its dates and names instead of on whether a public root
// signed it.
func (n *Net) TrustCABundle(path string) error {
	pool, err := LoadCABundle(path)
	if err != nil {
		return err
	}
	n.Roots = pool
	tr, _ := http.DefaultTransport.(*http.Transport)
	if tr != nil {
		tr = tr.Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
		n.Client.Transport = tr
	}
	return nil
}

func NewNet(timeout time.Duration) *Net {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Net{
		Timeout: timeout,
		Client: &http.Client{
			Timeout: timeout,
			// Redirects are followed for reachability, but a registry's 401 must
			// come back as 401 rather than being chased.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// Probe reports whether an endpoint answered at all. Any HTTP status counts as
// reachable — including 401 and 404 — because the question is whether DNS,
// routing, TLS and a live service exist, not whether we are authorised.
func (n *Net) Probe(ctx context.Context, url string) HTTPResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return HTTPResult{Err: err.Error()}
	}
	req.Header.Set("User-Agent", "budctl/1.0")
	resp, err := n.Client.Do(req)
	lat := time.Since(start)
	if err != nil {
		return HTTPResult{Err: cleanErr(err), Latency: lat}
	}
	defer resp.Body.Close()
	out := HTTPResult{Reachable: true, Status: resp.StatusCode, Latency: lat}
	if t, perr := http.ParseTime(resp.Header.Get("Date")); perr == nil {
		out.ServerTime = t
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		out.TLSIssuer = leaf.Issuer.CommonName
		out.TLSExpiry = leaf.NotAfter
	}
	return out
}

// TLSInspect opens a TLS connection and returns the served leaf certificate,
// used to check chain validity, expiry and SAN coverage for ingress hostnames.
func (n *Net) TLSInspect(ctx context.Context, host string, port int) (issuer string, expiry time.Time, sans []string, err error) {
	d := &net.Dialer{Timeout: n.Timeout}
	conn, err := tls.DialWithDialer(d, "tcp", fmt.Sprintf("%s:%d", host, port),
		&tls.Config{ServerName: host, RootCAs: n.Roots})
	if err != nil {
		// Retry without verification so an expired or self-signed certificate is
		// reported as what it is rather than as "unreachable". The verification
		// error is carried through: "signed by unknown authority" and "expired"
		// call for different actions, and collapsing them to "did not verify"
		// makes the operator dial the host by hand to find out which it is.
		why := tlsVerifyReason(err)
		conn, err = tls.DialWithDialer(d, "tcp", fmt.Sprintf("%s:%d", host, port),
			&tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err != nil {
			return "", time.Time{}, nil, err
		}
		defer conn.Close()
		leaf := conn.ConnectionState().PeerCertificates[0]
		return leaf.Issuer.CommonName, leaf.NotAfter, leaf.DNSNames, errors.New(why)
	}
	defer conn.Close()
	leaf := conn.ConnectionState().PeerCertificates[0]
	return leaf.Issuer.CommonName, leaf.NotAfter, leaf.DNSNames, nil
}

// LoadCABundle reads a PEM file into this host's trust store plus those roots.
// It is exported so the intake form can reject an unusable path while the
// operator is still looking at the field, rather than at the first handshake.
func LoadCABundle(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool, perr := x509.SystemCertPool()
	if perr != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return pool, nil
}

// tlsVerifyReason keeps the x509 cause and drops Go's wrapper prefix.
func tlsVerifyReason(err error) string {
	s := strings.TrimPrefix(err.Error(), "tls: failed to verify certificate: ")
	if s == "" {
		return "certificate did not verify"
	}
	return s
}

// TCP reports whether a port accepts a connection. github.com:22 is the reason
// this exists: a 443-only egress policy breaks ArgoCD silently.
func (n *Net) TCP(ctx context.Context, host string, port int) (bool, string) {
	d := net.Dialer{Timeout: n.Timeout}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, cleanErr(err)
	}
	_ = conn.Close()
	return true, ""
}

// Resolve returns the A/AAAA records for a hostname.
func (n *Net) Resolve(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	return addrs, err
}

// cleanErr strips the repetitive net/url wrapper so a failure detail reads as a
// cause rather than as a stack of prefixes.
func cleanErr(err error) string {
	s := err.Error()
	for _, p := range []string{`Get "`, `dial tcp: `} {
		if i := strings.Index(s, p); i >= 0 {
			if j := strings.Index(s, `": `); j > i {
				s = s[j+3:]
			}
		}
	}
	if strings.Contains(s, "no such host") {
		return "DNS: no such host"
	}
	if strings.Contains(s, "context deadline exceeded") || strings.Contains(s, "Client.Timeout") {
		return "timed out"
	}
	if strings.Contains(s, "connection refused") {
		return "connection refused"
	}
	if strings.Contains(s, "x509") {
		return "TLS: " + s
	}
	return s
}
