package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestInfoBPMPackageLocalFile(t *testing.T) {
	want := "# hello-bee-world\n\nHello from README.\n"
	packagePath := buildTestBPMPackageWithReadme(t, want)

	info, err := infoBPMPackage(context.Background(), packagePath, nil)
	if err != nil {
		t.Fatalf("infoBPMPackage() error = %v", err)
	}
	if info.Readme != want {
		t.Fatalf("README = %q, want %q", info.Readme, want)
	}
}

func TestInfoBPMPackageOCIReference(t *testing.T) {
	want := "# hello-bee-world\n\nHello from OCI README.\n"
	packagePath := buildTestBPMPackageWithReadme(t, want)
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

	info, err := infoBPMPackage(context.Background(), "oci://registry.test/isovalent-dev/hello-bee-world:0.1.0", httpClient)
	if err != nil {
		t.Fatalf("infoBPMPackage() error = %v", err)
	}
	if info.Readme != want {
		t.Fatalf("README = %q, want %q", info.Readme, want)
	}
}

func TestInfoBPMPackageRejectsMissingReadme(t *testing.T) {
	packagePath, _ := buildTestBPMPackageWithCert(t)

	_, err := infoBPMPackage(context.Background(), packagePath, nil)
	if err == nil {
		t.Fatalf("infoBPMPackage() error = nil, want error")
	}
	if !strings.Contains(err.Error(), defaultBPMReadmeFile) {
		t.Fatalf("error = %v", err)
	}
}

func buildTestBPMPackageWithReadme(t *testing.T, readme string) string {
	t.Helper()

	outputPath, err := buildBPMPackage(t.TempDir(), testBPMBuildFile(), bpmPackageMetadata{
		Name:        "hello-bee-world",
		Description: "Minimal hello-bee-world BPF package example",
		License:     "Apache-2.0",
		Authors:     []string{"Isovalent"},
	}, "0.1.0", bpmPackageFile{
		Target: defaultBPMReadmeFile,
		Body:   []byte(readme),
		Mode:   0o644,
	})
	if err != nil {
		t.Fatalf("buildBPMPackage() error = %v", err)
	}

	return outputPath
}
