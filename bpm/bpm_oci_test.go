package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBPMOCIRepository(t *testing.T) {
	repo, err := parseBPMOCIRepository("oci://quay.io/isovalent-dev/hello-bee-world")
	if err != nil {
		t.Fatalf("parseBPMOCIRepository() error = %v", err)
	}
	if repo.Registry != "quay.io" {
		t.Fatalf("Registry = %q", repo.Registry)
	}
	if repo.Name != "isovalent-dev/hello-bee-world" {
		t.Fatalf("Name = %q", repo.Name)
	}
	if repo.reference("0.1.0") != "oci://quay.io/isovalent-dev/hello-bee-world:0.1.0" {
		t.Fatalf("reference = %q", repo.reference("0.1.0"))
	}
}

func TestParseBPMOCIRepositoryRejectsMissingScheme(t *testing.T) {
	_, err := parseBPMOCIRepository("quay.io/isovalent-dev/hello-bee-world")
	if err == nil {
		t.Fatalf("parseBPMOCIRepository() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "oci://") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseBPMOCIRepositoryRejectsTag(t *testing.T) {
	_, err := parseBPMOCIRepository("oci://quay.io/isovalent-dev/hello-bee-world:0.1.0")
	if err == nil {
		t.Fatalf("parseBPMOCIRepository() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "must not include a tag") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseBPMOCIReference(t *testing.T) {
	ref, err := parseBPMOCIReference("oci://quay.io/isovalent-dev/hello-bee-world:0.1.0")
	if err != nil {
		t.Fatalf("parseBPMOCIReference() error = %v", err)
	}
	if ref.Repository.Registry != "quay.io" {
		t.Fatalf("Registry = %q", ref.Repository.Registry)
	}
	if ref.Repository.Name != "isovalent-dev/hello-bee-world" {
		t.Fatalf("Name = %q", ref.Repository.Name)
	}
	if ref.Tag != "0.1.0" {
		t.Fatalf("Tag = %q", ref.Tag)
	}
}

func TestParseBPMOCIReferenceRejectsMissingTag(t *testing.T) {
	_, err := parseBPMOCIReference("oci://quay.io/isovalent-dev/hello-bee-world")
	if err == nil {
		t.Fatalf("parseBPMOCIReference() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "include a tag") {
		t.Fatalf("error = %v", err)
	}
}

func TestBPMOCIRejectsInvalidScheme(t *testing.T) {
	t.Setenv("BPM_OCI_SCHEME", "ftp")
	client := newBPMOCIRegistryClient("registry.test", "example/package", nil)
	_, err := client.do(context.Background(), http.MethodGet,
		client.url("/v2/example/package/manifests/stable"), nil, "", "", "")
	if err == nil || !strings.Contains(err.Error(), "BPM_OCI_SCHEME") {
		t.Fatalf("error = %v, want BPM_OCI_SCHEME diagnostic", err)
	}
}

func TestBPMOCIRejectsInvalidCAFile(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "not-a-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	t.Setenv("BPM_OCI_CA_FILE", caPath)
	client := newBPMOCIRegistryClient("registry.test", "example/package", nil)
	_, err := client.do(context.Background(), http.MethodGet,
		client.url("/v2/example/package/manifests/stable"), nil, "", "", "")
	if err == nil || !strings.Contains(err.Error(), "valid PEM CA certificate") {
		t.Fatalf("error = %v, want CA diagnostic", err)
	}
}

func TestPutBPMPackage(t *testing.T) {
	packagePath, wantCertificate := buildTestBPMPackageWithCert(t)
	uploads := map[string][]byte{}
	var packageManifest bpmOCIManifest
	var packageManifestDigest string
	var publicKeyManifest bpmOCIManifest

	httpClient := &http.Client{Transport: bpmRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(request.URL.Path, "/v2/isovalent-dev/hello-bee-world/") {
			t.Fatalf("path = %s", request.URL.Path)
		}

		switch {
		case request.Method == http.MethodHead && strings.Contains(request.URL.Path, "/blobs/"):
			return bpmTestResponse(request, http.StatusNotFound, "", nil), nil
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/blobs/uploads/"):
			return bpmTestResponse(request, http.StatusAccepted, "", map[string]string{
				"Location": request.URL.Path + "upload-id",
			}), nil
		case request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/blobs/uploads/upload-id"):
			digest := request.URL.Query().Get("digest")
			if digest == "" {
				t.Fatalf("missing digest query")
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("read upload body: %v", err)
			}
			uploads[digest] = body
			return bpmTestResponse(request, http.StatusCreated, "", nil), nil
		case request.Method == http.MethodPut && strings.HasSuffix(request.URL.Path, "/manifests/0.1.0"):
			if request.Header.Get("Content-Type") != bpmOCIManifestMediaType {
				t.Fatalf("Content-Type = %q", request.Header.Get("Content-Type"))
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			packageManifestDigest = digestBytes(body)
			if err := json.Unmarshal(body, &packageManifest); err != nil {
				t.Fatalf("decode manifest: %v", err)
			}
			return bpmTestResponse(request, http.StatusCreated, "", nil), nil
		case request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/manifests/sha256:"):
			if request.Header.Get("Content-Type") != bpmOCIManifestMediaType {
				t.Fatalf("Content-Type = %q", request.Header.Get("Content-Type"))
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("read public key manifest: %v", err)
			}
			if err := json.Unmarshal(body, &publicKeyManifest); err != nil {
				t.Fatalf("decode public key manifest: %v", err)
			}
			return bpmTestResponse(request, http.StatusCreated, "", nil), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
		return nil, nil
	})}

	repository := "oci://registry.test/isovalent-dev/hello-bee-world"
	ref, err := putBPMPackage(context.Background(), packagePath, repository, httpClient)
	if err != nil {
		t.Fatalf("putBPMPackage() error = %v", err)
	}
	if ref != repository+":0.1.0" {
		t.Fatalf("ref = %q, want %q", ref, repository+":0.1.0")
	}

	if len(uploads) != 4 {
		t.Fatalf("len(uploads) = %d, want 4", len(uploads))
	}
	if packageManifest.MediaType != bpmOCIManifestMediaType {
		t.Fatalf("manifest media type = %q", packageManifest.MediaType)
	}
	if len(packageManifest.Layers) != 1 {
		t.Fatalf("len(manifest.Layers) = %d, want 1", len(packageManifest.Layers))
	}
	if packageManifest.Layers[0].MediaType != bpmOCIPackageLayerMediaType {
		t.Fatalf("layer media type = %q", packageManifest.Layers[0].MediaType)
	}
	if packageManifest.Annotations["dev.isovalent.bpm.package.name"] != "hello-bee-world" {
		t.Fatalf("annotations = %#v", packageManifest.Annotations)
	}
	if packageManifest.Annotations["dev.isovalent.bpm.package.version"] != "0.1.0" {
		t.Fatalf("annotations = %#v", packageManifest.Annotations)
	}

	if publicKeyManifest.ArtifactType != bpmOCIPublicKeyArtifactType {
		t.Fatalf("public key artifact type = %q", publicKeyManifest.ArtifactType)
	}
	if publicKeyManifest.Subject == nil {
		t.Fatalf("public key manifest subject = nil")
	}
	if publicKeyManifest.Subject.Digest != packageManifestDigest {
		t.Fatalf("public key subject digest = %q, want %q", publicKeyManifest.Subject.Digest, packageManifestDigest)
	}
	if publicKeyManifest.Subject.MediaType != bpmOCIManifestMediaType {
		t.Fatalf("public key subject media type = %q", publicKeyManifest.Subject.MediaType)
	}
	if len(publicKeyManifest.Layers) != 1 {
		t.Fatalf("len(publicKeyManifest.Layers) = %d, want 1", len(publicKeyManifest.Layers))
	}
	if publicKeyManifest.Layers[0].MediaType != bpmOCIPublicKeyMediaType {
		t.Fatalf("public key layer media type = %q", publicKeyManifest.Layers[0].MediaType)
	}
	if string(uploads[publicKeyManifest.Layers[0].Digest]) != string(wantCertificate) {
		t.Fatalf("uploaded public certificate body mismatch")
	}
	if publicKeyManifest.Annotations != nil {
		t.Fatalf("public key annotations = %#v", publicKeyManifest.Annotations)
	}
	if publicKeyManifest.Layers[0].Annotations != nil {
		t.Fatalf("public key layer annotations = %#v", publicKeyManifest.Layers[0].Annotations)
	}
}

func TestPutBPMPackageRejectsCrossOriginUploadLocation(t *testing.T) {
	packagePath, _ := buildTestBPMPackageWithCert(t)
	httpClient := &http.Client{Transport: bpmRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodHead:
			return bpmTestResponse(request, http.StatusNotFound, "", nil), nil
		case request.Method == http.MethodPost:
			return bpmTestResponse(request, http.StatusAccepted, "", map[string]string{
				"Location": "https://uploads.example.invalid/v2/upload-id",
			}), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})}

	_, err := putBPMPackage(context.Background(), packagePath,
		"oci://registry.test/isovalent-dev/hello-bee-world", httpClient)
	if err == nil {
		t.Fatalf("putBPMPackage() error = nil, want cross-origin rejection")
	}
	if !strings.Contains(err.Error(), "different origin") {
		t.Fatalf("error = %v, want different-origin diagnostic", err)
	}
}

func TestPutBPMPackageRejectsMissingPublicCertificate(t *testing.T) {
	packagePath := buildTestBPMPackageWithoutCert(t)
	httpClient := &http.Client{Transport: bpmRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		return nil, nil
	})}

	_, err := putBPMPackage(context.Background(), packagePath, "oci://registry.test/isovalent-dev/hello-bee-world", httpClient)
	if err == nil {
		t.Fatalf("putBPMPackage() error = nil, want error")
	}
	if !strings.Contains(err.Error(), defaultBPMBuildPublicCertificateFile) {
		t.Fatalf("error = %v", err)
	}
}

func TestGetBPMPackage(t *testing.T) {
	packagePath := buildTestBPMPackage(t)
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
			Annotations: map[string]string{
				"org.opencontainers.image.title": "hello-bee-world-0.1.0.bee",
			},
		}},
		Annotations: map[string]string{
			"dev.isovalent.bpm.package.name":    "hello-bee-world",
			"dev.isovalent.bpm.package.version": "0.1.0",
		},
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
			if request.Header.Get("Accept") != bpmOCIManifestMediaType {
				t.Fatalf("Accept = %q", request.Header.Get("Accept"))
			}
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

	outputDir := t.TempDir()
	outputPath, err := getBPMPackage(context.Background(), "oci://registry.test/isovalent-dev/hello-bee-world:0.1.0", outputDir, httpClient)
	if err != nil {
		t.Fatalf("getBPMPackage() error = %v", err)
	}
	wantPath := filepath.Join(outputDir, "hello-bee-world-0.1.0.bee")
	if outputPath != wantPath {
		t.Fatalf("outputPath = %q, want %q", outputPath, wantPath)
	}

	body, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read downloaded package: %v", err)
	}
	if string(body) != string(archive.Body) {
		t.Fatalf("downloaded package body mismatch")
	}
}

func TestReadBPMRegistryCredentialsUsesCredsStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
		"auths": {
			"quay.io": {}
		},
		"credsStore": "testhelper"
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	oldHelperGet := bpmDockerCredentialHelperGet
	bpmDockerCredentialHelperGet = func(helperName string, registry string) (bpmRegistryCredentials, bool) {
		if helperName != "testhelper" {
			t.Fatalf("helperName = %q", helperName)
		}
		if registry != "quay.io" {
			t.Fatalf("registry = %q", registry)
		}
		return bpmRegistryCredentials{username: "robot", password: "token"}, true
	}
	t.Cleanup(func() {
		bpmDockerCredentialHelperGet = oldHelperGet
	})

	credentials, ok := readBPMRegistryCredentials(path, "quay.io")
	if !ok {
		t.Fatalf("readBPMRegistryCredentials() ok = false")
	}
	if credentials.username != "robot" || credentials.password != "token" {
		t.Fatalf("credentials = %#v", credentials)
	}
}

func TestReadBPMRegistryCredentialsUsesCredHelperOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
		"auths": {
			"quay.io": {}
		},
		"credsStore": "fallback",
		"credHelpers": {
			"quay.io": "quayhelper"
		}
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	oldHelperGet := bpmDockerCredentialHelperGet
	bpmDockerCredentialHelperGet = func(helperName string, registry string) (bpmRegistryCredentials, bool) {
		if helperName != "quayhelper" {
			t.Fatalf("helperName = %q", helperName)
		}
		if registry != "quay.io" {
			t.Fatalf("registry = %q", registry)
		}
		return bpmRegistryCredentials{username: "robot", password: "token"}, true
	}
	t.Cleanup(func() {
		bpmDockerCredentialHelperGet = oldHelperGet
	})

	if _, ok := readBPMRegistryCredentials(path, "quay.io"); !ok {
		t.Fatalf("readBPMRegistryCredentials() ok = false")
	}
}

func buildTestBPMPackage(t *testing.T) string {
	t.Helper()

	outputPath, _ := buildTestBPMPackageWithCert(t)

	return outputPath
}

func buildTestBPMPackageWithCert(t *testing.T) (string, []byte) {
	t.Helper()

	keysDir := filepath.Join(t.TempDir(), "keys")
	fingerprint := writeTestBPMShirudoCert(t, keysDir)
	certPath := filepath.Join(keysDir, "cert.der")
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert.der: %v", err)
	}
	environmentBody, err := json.Marshal(bpmBuildEnvironment{
		Shirudo: bpmBuildEnvironmentShirudo{
			SPKISHA256Fingerprint: fingerprint,
		},
	})
	if err != nil {
		t.Fatalf("marshal build environment: %v", err)
	}

	outputPath, err := buildBPMPackage(t.TempDir(), testBPMBuildFile(), bpmPackageMetadata{
		Name:        "hello-bee-world",
		Description: "Minimal hello-bee-world BPF package example",
		License:     "Apache-2.0",
		Authors:     []string{"Isovalent"},
	}, "0.1.0", bpmPackageFile{
		Target: defaultBPMBuildEnvironmentFile,
		Body:   environmentBody,
		Mode:   0o644,
	}, bpmPackageFile{
		Target: defaultBPMBuildPublicCertificateFile,
		Body:   certificate,
		Mode:   0o644,
	})
	if err != nil {
		t.Fatalf("buildBPMPackage() error = %v", err)
	}

	return filepath.Clean(outputPath), certificate
}

func buildTestBPMPackageWithoutCert(t *testing.T) string {
	t.Helper()

	keysDir := filepath.Join(t.TempDir(), "keys")
	fingerprint := writeTestBPMShirudoCert(t, keysDir)
	environmentBody, err := json.Marshal(bpmBuildEnvironment{
		Shirudo: bpmBuildEnvironmentShirudo{
			SPKISHA256Fingerprint: fingerprint,
		},
	})
	if err != nil {
		t.Fatalf("marshal build environment: %v", err)
	}

	outputPath, err := buildBPMPackage(t.TempDir(), testBPMBuildFile(), bpmPackageMetadata{
		Name:        "hello-bee-world",
		Description: "Minimal hello-bee-world BPF package example",
		License:     "Apache-2.0",
		Authors:     []string{"Isovalent"},
	}, "0.1.0", bpmPackageFile{
		Target: defaultBPMBuildEnvironmentFile,
		Body:   environmentBody,
		Mode:   0o644,
	})
	if err != nil {
		t.Fatalf("buildBPMPackage() error = %v", err)
	}

	return filepath.Clean(outputPath)
}

type bpmRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn bpmRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func bpmTestResponse(request *http.Request, statusCode int, body string, headers map[string]string) *http.Response {
	return bpmTestResponseBytes(request, statusCode, []byte(body), headers)
}

func bpmTestResponseBytes(request *http.Request, statusCode int, body []byte, headers map[string]string) *http.Response {
	response := &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Header:     make(http.Header),
		Request:    request,
	}
	for key, value := range headers {
		response.Header.Set(key, value)
	}
	return response
}
