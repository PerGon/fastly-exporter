package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

// BackendCert holds the mTLS client certificate expiry of a single backend
// (origin) in the active version of a service.
type BackendCert struct {
	ServiceID   string
	ServiceName string
	Backend     string
	NotAfter    time.Time
}

// BackendCertCache polls api.fastly.com/service/%s/version/%d/backend for the
// active version of each service and caches the expiry of every backend's
// ssl_client_cert. That information is exposed as Prometheus metrics.
type BackendCertCache struct {
	client       HTTPClient
	token        string
	logger       log.Logger
	serviceCache *ServiceCache
	enabled      bool

	mtx   sync.RWMutex
	certs []BackendCert
}

// NewBackendCertCache returns an empty cache. Use the Refresh method to update it.
func NewBackendCertCache(client HTTPClient, token string, logger log.Logger, serviceCache *ServiceCache, enabled bool) *BackendCertCache {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	return &BackendCertCache{
		client:       client,
		token:        token,
		logger:       log.With(logger, "component", "backend-cert"),
		serviceCache: serviceCache,
		enabled:      enabled,
	}
}

// Enabled returns true if the BackendCertCache is enabled.
func (c *BackendCertCache) Enabled() bool { return c.enabled }

// Refresh queries the Fastly API and rebuilds the in-memory snapshot. A failure
// for one service is logged and skipped so it doesn't hide the others.
func (c *BackendCertCache) Refresh(ctx context.Context) error {
	if !c.enabled {
		return nil
	}
	out := []BackendCert{}
	for _, s := range c.serviceCache.Services() {
		if s.Version <= 0 {
			continue
		}
		backends, err := c.listBackends(ctx, s.ID, s.Version)
		if err != nil {
			if e, ok := err.(*Error); ok && e.Code == http.StatusForbidden && c.Certs() == nil {
				c.enabled = false
				return err
			}
			level.Warn(c.logger).Log("during", "list backends", "service", s.ID, "err", err)
			continue
		}
		for _, b := range backends {
			if b.SSLClientCert == "" {
				continue
			}
			notAfter, err := parseCertNotAfter(b.SSLClientCert)
			if err != nil {
				level.Warn(c.logger).Log("during", "parse client cert", "service", s.ID, "backend", b.Name, "err", err)
				continue
			}
			out = append(out, BackendCert{ServiceID: s.ID, ServiceName: s.Name, Backend: b.Name, NotAfter: notAfter})
		}
	}

	c.mtx.Lock()
	c.certs = out
	c.mtx.Unlock()

	level.Debug(c.logger).Log("msg", "refreshed backend client certs", "rows", len(out))
	return nil
}

// Certs returns the currently cached backend certificates.
func (c *BackendCertCache) Certs() []BackendCert {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return c.certs
}

type backendResp struct {
	Name          string `json:"name"`
	SSLClientCert string `json:"ssl_client_cert"`
}

func (c *BackendCertCache) listBackends(ctx context.Context, serviceID string, version int) ([]backendResp, error) {
	u := fmt.Sprintf("https://api.fastly.com/service/%s/version/%d/backend", serviceID, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Fastly-Key", c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, NewError(resp)
	}
	var backends []backendResp
	return backends, json.NewDecoder(resp.Body).Decode(&backends)
}

// parseCertNotAfter returns the expiry of the first certificate in a PEM bundle
// (the leaf, by convention).
func parseCertNotAfter(p string) (time.Time, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

type backendCertCollector struct {
	cache *BackendCertCache
	desc  *prometheus.Desc
}

func (bc *backendCertCollector) Describe(ch chan<- *prometheus.Desc) { ch <- bc.desc }

// Collect computes the remaining lifetime at scrape time so the value keeps
// counting down between refreshes.
func (bc *backendCertCollector) Collect(ch chan<- prometheus.Metric) {
	for _, r := range bc.cache.Certs() {
		ch <- prometheus.MustNewConstMetric(bc.desc, prometheus.GaugeValue, time.Until(r.NotAfter).Seconds(), r.ServiceID, r.ServiceName, r.Backend)
	}
}

// Gatherer returns a prometheus.Gatherer backed by a custom collector.
func (c *BackendCertCache) Gatherer(namespace, subsystem string) (prometheus.Gatherer, error) {
	if !c.enabled {
		return prometheus.Gatherers{}, nil
	}
	desc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "backend_mtls_client_cert_expiry_seconds"),
		"Seconds until the mTLS client certificate of a backend (origin) in the active service version expires; negative if already expired.",
		[]string{"service_id", "service_name", "backend"}, nil,
	)
	reg := prometheus.NewRegistry()
	if err := reg.Register(&backendCertCollector{cache: c, desc: desc}); err != nil {
		return nil, fmt.Errorf("registering backend cert collector: %w", err)
	}
	return reg, nil
}
