package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/fastly/fastly-exporter/pkg/api"
	"github.com/go-kit/log"
	"github.com/google/go-cmp/cmp"
)

func TestBackendCertCache(t *testing.T) {
	t.Parallel()

	svcClient := fixedResponseClient{code: 200, response: serviceResponseForDictionaryInfo}
	serviceCache := api.NewServiceCache(svcClient, "irrelevant_token")
	serviceCache.Refresh(context.Background())

	notAfter := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	backends, _ := json.Marshal([]map[string]string{
		{"name": "origin-mtls", "ssl_client_cert": selfSignedPEM(t, notAfter)},
		{"name": "origin-plain", "ssl_client_cert": ""},
	})

	for _, testcase := range []struct {
		name        string
		client      api.HTTPClient
		wantCerts   []api.BackendCert
		wantErr     error
		wantEnabled bool
	}{
		{
			name:   "success",
			client: fixedResponseClient{code: http.StatusOK, response: string(backends)},
			wantCerts: []api.BackendCert{
				{ServiceID: "qwertMz1ncwA0KC3TBloku", ServiceName: "test", Backend: "origin-mtls", NotAfter: notAfter},
			},
			wantEnabled: true,
		},
		{
			name:        "forbidden",
			client:      fixedResponseClient{code: http.StatusForbidden},
			wantErr:     &api.Error{Code: http.StatusForbidden},
			wantEnabled: false,
		},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			cache := api.NewBackendCertCache(testcase.client, "irrelevant token", log.NewNopLogger(), serviceCache, true)

			if want, have := testcase.wantErr, cache.Refresh(context.Background()); !cmp.Equal(want, have) {
				t.Fatal(cmp.Diff(want, have))
			}
			if want, have := testcase.wantCerts, cache.Certs(); !cmp.Equal(want, have) {
				t.Fatal(cmp.Diff(want, have))
			}
			if want, have := testcase.wantEnabled, cache.Enabled(); want != have {
				t.Fatalf("enabled: want %v, have %v", want, have)
			}
		})
	}
}

func selfSignedPEM(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
