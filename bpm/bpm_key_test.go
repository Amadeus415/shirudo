package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestAddBPMKeyLocalPackage(t *testing.T) {
	packagePath, certificate := buildTestBPMPackageWithCert(t)
	want, err := bpmSPKISHA256Fingerprint(certificate)
	if err != nil {
		t.Fatalf("bpmSPKISHA256Fingerprint() error = %v", err)
	}

	keysDir := t.TempDir()
	result, err := addBPMKey(context.Background(), packagePath, keysDir, nil)
	if err != nil {
		t.Fatalf("addBPMKey() error = %v", err)
	}
	if result.Fingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", result.Fingerprint, want)
	}
	if !result.Active {
		t.Fatalf("Active = false")
	}

	keyPath := filepath.Join(keysDir, want+".der")
	body, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if string(body) != string(certificate) {
		t.Fatalf("key body mismatch")
	}

	activeTarget, err := os.Readlink(filepath.Join(keysDir, defaultBPMBuildPublicCertificateFile))
	if err != nil {
		t.Fatalf("read active key symlink: %v", err)
	}
	if activeTarget != filepath.Base(keyPath) {
		t.Fatalf("active key symlink = %q, want %q", activeTarget, filepath.Base(keyPath))
	}
}

func TestAddBPMKeyIdempotent(t *testing.T) {
	packagePath, _ := buildTestBPMPackageWithCert(t)
	keysDir := t.TempDir()

	first, err := addBPMKey(context.Background(), packagePath, keysDir, nil)
	if err != nil {
		t.Fatalf("first addBPMKey() error = %v", err)
	}
	second, err := addBPMKey(context.Background(), packagePath, keysDir, nil)
	if err != nil {
		t.Fatalf("second addBPMKey() error = %v", err)
	}
	if second.Fingerprint != first.Fingerprint {
		t.Fatalf("second fingerprint = %q, want %q", second.Fingerprint, first.Fingerprint)
	}
}

func TestAddBPMKeyRefusesDifferentActiveCertificate(t *testing.T) {
	packagePath, _ := buildTestBPMPackageWithCert(t)
	keysDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keysDir, defaultBPMBuildPublicCertificateFile), []byte("different certificate\n"), 0o644); err != nil {
		t.Fatalf("write active cert: %v", err)
	}

	_, err := addBPMKey(context.Background(), packagePath, keysDir, nil)
	if err == nil {
		t.Fatalf("addBPMKey() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "already exists and differs") {
		t.Fatalf("error = %v", err)
	}
}

func TestAddBPMKeyOCIReference(t *testing.T) {
	packagePath, certificate := buildTestBPMPackageWithCert(t)
	want, err := bpmSPKISHA256Fingerprint(certificate)
	if err != nil {
		t.Fatalf("bpmSPKISHA256Fingerprint() error = %v", err)
	}
	archive, err := loadBPMPackageArchive(packagePath)
	if err != nil {
		t.Fatalf("loadBPMPackageArchive() error = %v", err)
	}

	manifest := bpmOCIManifest{
		SchemaVersion: 2,
		MediaType:     bpmOCIManifestMediaType,
		Config: bpmOCIDescriptor{
			MediaType: bpmOCIConfigMediaType,
			Digest:    digestBytes([]byte("{}")),
			Size:      2,
		},
		Layers: []bpmOCIDescriptor{{
			MediaType: bpmOCIPackageLayerMediaType,
			Digest:    digestBytes(archive.Body),
			Size:      int64(len(archive.Body)),
		}},
	}
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	httpClient := &http.Client{Transport: bpmRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(request.URL.Path, "/v2/isovalent-dev/hello-bee-world/") {
			t.Fatalf("path = %s", request.URL.Path)
		}

		switch {
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/manifests/0.1.0"):
			return bpmTestResponse(request, http.StatusOK, string(manifestBody), map[string]string{
				"Content-Type": bpmOCIManifestMediaType,
			}), nil
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/blobs/"):
			return bpmTestResponseBytes(request, http.StatusOK, archive.Body, map[string]string{
				"Content-Type": bpmOCIPackageLayerMediaType,
			}), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
		return nil, nil
	})}

	keysDir := t.TempDir()
	result, err := addBPMKey(context.Background(), "oci://registry.test/isovalent-dev/hello-bee-world:0.1.0", keysDir, httpClient)
	if err != nil {
		t.Fatalf("addBPMKey() error = %v", err)
	}
	if result.Fingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", result.Fingerprint, want)
	}
	if _, err := os.Stat(filepath.Join(keysDir, want+".der")); err != nil {
		t.Fatalf("stat key file: %v", err)
	}
}

func TestListBPMKeys(t *testing.T) {
	keysDir := t.TempDir()
	firstFingerprint, firstCertificate := testBPMKeyCertificate(t, 1)
	secondFingerprint, secondCertificate := testBPMKeyCertificate(t, 2)

	if err := os.WriteFile(filepath.Join(keysDir, secondFingerprint+".der"), secondCertificate, 0o644); err != nil {
		t.Fatalf("write second key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, strings.ToUpper(firstFingerprint)+".DER"), firstCertificate, 0o644); err != nil {
		t.Fatalf("write first key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, defaultBPMBuildPublicCertificateFile), firstCertificate, 0o644); err != nil {
		t.Fatalf("write active key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "not-a-key.der"), firstCertificate, 0o644); err != nil {
		t.Fatalf("write non-key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, strings.Repeat("0", 64)+".der"), firstCertificate, 0o644); err != nil {
		t.Fatalf("write mismatched key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, strings.Repeat("f", 64)+".der"), []byte("not a cert\n"), 0o644); err != nil {
		t.Fatalf("write invalid key: %v", err)
	}
	if err := os.Mkdir(filepath.Join(keysDir, strings.Repeat("a", 64)+".der"), 0o755); err != nil {
		t.Fatalf("write key-like directory: %v", err)
	}

	got, err := listBPMKeys(keysDir)
	if err != nil {
		t.Fatalf("listBPMKeys() error = %v", err)
	}
	want := []string{firstFingerprint, secondFingerprint}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %#v, want %#v", got, want)
	}
}

func TestListBPMKeysMissingDirectory(t *testing.T) {
	keysDir := filepath.Join(t.TempDir(), "missing")

	got, err := listBPMKeys(keysDir)
	if err != nil {
		t.Fatalf("listBPMKeys() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("keys = %#v, want empty", got)
	}
	if _, err := os.Stat(keysDir); !os.IsNotExist(err) {
		t.Fatalf("keys dir was created, stat err = %v", err)
	}
}

func testBPMKeyCertificate(t *testing.T, seedByte byte) (string, []byte) {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(seedByte)),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(4102444800, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	fingerprint := sha256.Sum256(publicKeyDER)

	return hex.EncodeToString(fingerprint[:]), certificate
}
