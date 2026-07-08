package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInstallBPMPackageArchiveExtractsAndLoadsUpatches(t *testing.T) {
	body := buildTestBPMPackageBodyWithUpatch(t)
	installRoot := t.TempDir()
	wantRoot, err := filepath.EvalSymlinks(installRoot)
	if err != nil {
		t.Fatalf("resolve install root: %v", err)
	}

	var loaded []string
	var configs [][]string
	oldLoad := bpmShirudoUpatchLoad
	bpmShirudoUpatchLoad = func(ctx context.Context, upatchPath string, configPaths []string, stdout io.Writer, stderr io.Writer) error {
		loaded = append(loaded, upatchPath)
		configs = append(configs, append([]string(nil), configPaths...))
		return nil
	}
	t.Cleanup(func() {
		bpmShirudoUpatchLoad = oldLoad
	})

	installDir, err := installBPMPackageArchive(context.Background(), body, installRoot, nil, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("installBPMPackageArchive() error = %v", err)
	}

	wantDir := filepath.Join(wantRoot, "hello-bee-world-0.1.0")
	if installDir != wantDir {
		t.Fatalf("installDir = %q, want %q", installDir, wantDir)
	}
	if _, err := os.Stat(filepath.Join(wantDir, defaultBPMBuildFile)); err != nil {
		t.Fatalf("stat Beefile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(wantDir, "src", "hello-userns-counter.bpf.c")); err != nil {
		t.Fatalf("stat source: %v", err)
	}
	wantUpatch := filepath.Join(wantDir, "upatches", "hello-userns-counter.upatch")
	if body, err := os.ReadFile(wantUpatch); err != nil {
		t.Fatalf("read upatch: %v", err)
	} else if string(body) != "upatch\n" {
		t.Fatalf("upatch body = %q", body)
	}
	if len(loaded) != 1 || loaded[0] != wantUpatch {
		t.Fatalf("loaded = %#v, want [%q]", loaded, wantUpatch)
	}
	if len(configs) != 1 || len(configs[0]) != 0 {
		t.Fatalf("configs = %#v, want empty config path", configs)
	}
}

func TestInstallBPMPackageArchivePassesPackageConfigBeforeAdditionalConfigFiles(t *testing.T) {
	configBody := []byte(`# bpm treats this file as opaque input for shirudo upatch load.
[runtime]
sample_rate = "not validated by bpm"
`)
	body := buildTestBPMPackageBodyWithConfig(t, configBody)
	installRoot := t.TempDir()
	additionalConfigs := []string{"/user/first.toml", "/user/second.toml"}

	oldLoad := bpmShirudoUpatchLoad
	var loadedUpatch string
	var loadedConfigs []string
	bpmShirudoUpatchLoad = func(ctx context.Context, upatchPath string, configPaths []string, stdout io.Writer, stderr io.Writer) error {
		loadedUpatch = upatchPath
		loadedConfigs = append([]string(nil), configPaths...)
		return nil
	}
	t.Cleanup(func() {
		bpmShirudoUpatchLoad = oldLoad
	})

	installDir, err := installBPMPackageArchive(context.Background(), body, installRoot, additionalConfigs, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("installBPMPackageArchive() error = %v", err)
	}

	wantUpatch := filepath.Join(installDir, "upatches", "hello-userns-counter.upatch")
	if loadedUpatch != wantUpatch {
		t.Fatalf("loadedUpatch = %q, want %q", loadedUpatch, wantUpatch)
	}
	wantConfig := filepath.Join(installDir, defaultBPMConfigFile)
	wantConfigs := []string{wantConfig, "/user/first.toml", "/user/second.toml"}
	if !reflect.DeepEqual(loadedConfigs, wantConfigs) {
		t.Fatalf("loadedConfigs = %#v, want %#v", loadedConfigs, wantConfigs)
	}
	gotConfig, err := os.ReadFile(wantConfig)
	if err != nil {
		t.Fatalf("read installed config: %v", err)
	}
	if !bytes.Equal(gotConfig, configBody) {
		t.Fatalf("installed config = %q, want %q", gotConfig, configBody)
	}
}

func TestRunBPMShirudoUpatchLoadPassesConfigFlag(t *testing.T) {
	argsPath := installFakeBPMShirudo(t)

	if err := runBPMShirudoUpatchLoad(context.Background(), "/pkg/upatches/drop.upatch", []string{"/pkg/config.toml", "/user/first.toml", "/user/second.toml"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("runBPMShirudoUpatchLoad() error = %v", err)
	}

	want := "upatch\nload\n-f\n/pkg/config.toml\n-f\n/user/first.toml\n-f\n/user/second.toml\n/pkg/upatches/drop.upatch\n"
	got, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read fake shirudo args: %v", err)
	}
	if string(got) != want {
		t.Fatalf("shirudo args = %q, want %q", got, want)
	}
}

func TestRunBPMShirudoUpatchLoadOmitsConfigFlagWithoutConfig(t *testing.T) {
	argsPath := installFakeBPMShirudo(t)

	if err := runBPMShirudoUpatchLoad(context.Background(), "/pkg/upatches/drop.upatch", nil, io.Discard, io.Discard); err != nil {
		t.Fatalf("runBPMShirudoUpatchLoad() error = %v", err)
	}

	want := "upatch\nload\n/pkg/upatches/drop.upatch\n"
	got, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read fake shirudo args: %v", err)
	}
	if string(got) != want {
		t.Fatalf("shirudo args = %q, want %q", got, want)
	}
}

func TestInstallBPMPackageArchiveRejectsInstalledVersionOfSamePackage(t *testing.T) {
	installRoot := t.TempDir()

	oldLoad := bpmShirudoUpatchLoad
	bpmShirudoUpatchLoad = func(ctx context.Context, upatchPath string, configPaths []string, stdout io.Writer, stderr io.Writer) error {
		return nil
	}
	t.Cleanup(func() {
		bpmShirudoUpatchLoad = oldLoad
	})

	if _, err := installBPMPackageArchive(context.Background(), buildTestBPMPackageBodyWithUpatchVersion(t, "0.1.0"), installRoot, nil, io.Discard, io.Discard); err != nil {
		t.Fatalf("install old package: %v", err)
	}

	loadCalled := false
	bpmShirudoUpatchLoad = func(ctx context.Context, upatchPath string, configPaths []string, stdout io.Writer, stderr io.Writer) error {
		loadCalled = true
		return nil
	}

	_, err := installBPMPackageArchive(context.Background(), buildTestBPMPackageBodyWithUpatchVersion(t, "0.2.0"), installRoot, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatalf("installBPMPackageArchive() error = nil, want error")
	}
	want := "hello-bee-world-0.1.0 is already installed; uninstall it first with: 'bpm uninstall hello-bee-world-0.1.0'"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if loadCalled {
		t.Fatalf("shirudo load was called before install conflict failed")
	}
	if _, err := os.Stat(filepath.Join(installRoot, "hello-bee-world-0.2.0")); !os.IsNotExist(err) {
		t.Fatalf("new package dir exists or stat failed: %v", err)
	}
}

func TestUninstallBPMPackageUnloadsAndRemovesInstallDir(t *testing.T) {
	body := buildTestBPMPackageBodyWithUpatch(t)
	installRoot := t.TempDir()

	oldLoad := bpmShirudoUpatchLoad
	bpmShirudoUpatchLoad = func(ctx context.Context, upatchPath string, configPaths []string, stdout io.Writer, stderr io.Writer) error {
		return nil
	}
	t.Cleanup(func() {
		bpmShirudoUpatchLoad = oldLoad
	})

	installDir, err := installBPMPackageArchive(context.Background(), body, installRoot, nil, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("installBPMPackageArchive() error = %v", err)
	}

	var unloaded []string
	oldUnload := bpmShirudoUpatchUnload
	bpmShirudoUpatchUnload = func(ctx context.Context, upatchPath string, stdout io.Writer, stderr io.Writer) error {
		unloaded = append(unloaded, upatchPath)
		return nil
	}
	t.Cleanup(func() {
		bpmShirudoUpatchUnload = oldUnload
	})

	removedDir, err := uninstallBPMPackage(context.Background(), "hello-bee-world-0.1.0", installRoot, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("uninstallBPMPackage() error = %v", err)
	}
	if removedDir != installDir {
		t.Fatalf("removedDir = %q, want %q", removedDir, installDir)
	}
	wantUnload := filepath.Join(installDir, "upatches", "hello-userns-counter.unload.upatch")
	if len(unloaded) != 1 || unloaded[0] != wantUnload {
		t.Fatalf("unloaded = %#v, want [%q]", unloaded, wantUnload)
	}
	if _, err := os.Stat(installDir); !os.IsNotExist(err) {
		t.Fatalf("install dir still exists or stat failed: %v", err)
	}
}

func TestListBPMInstalledPackages(t *testing.T) {
	installRoot := t.TempDir()
	for _, name := range []string{"hello-bee-world-0.1.0", "trace-open-2.0.0"} {
		if err := os.Mkdir(filepath.Join(installRoot, name), 0o755); err != nil {
			t.Fatalf("create package dir %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(installRoot, "not-a-package-file"), []byte("ignore\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	packages, err := listBPMInstalledPackages(installRoot)
	if err != nil {
		t.Fatalf("listBPMInstalledPackages() error = %v", err)
	}
	want := []string{"hello-bee-world-0.1.0", "trace-open-2.0.0"}
	if len(packages) != len(want) {
		t.Fatalf("packages = %#v, want %#v", packages, want)
	}
	for i := range want {
		if packages[i] != want[i] {
			t.Fatalf("packages = %#v, want %#v", packages, want)
		}
	}
}

func TestInstalledBPMPackageForNameRejectsPath(t *testing.T) {
	_, _, err := installedBPMPackageForName(t.TempDir(), "../hello-bee-world-0.1.0")
	if err == nil {
		t.Fatalf("installedBPMPackageForName() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "installed package directory name") {
		t.Fatalf("error = %v", err)
	}
}

func TestInstallBPMPackageDownloadsFromOCI(t *testing.T) {
	body := buildTestBPMPackageBodyWithUpatch(t)
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
			Digest:    digestBytes(body),
			Size:      int64(len(body)),
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
			return bpmTestResponse(request, http.StatusOK, string(manifestBody), map[string]string{
				"Content-Type": bpmOCIManifestMediaType,
			}), nil
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/blobs/"):
			return bpmTestResponseBytes(request, http.StatusOK, body, map[string]string{
				"Content-Type": bpmOCIPackageLayerMediaType,
			}), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
		return nil, nil
	})}

	var loaded []string
	oldLoad := bpmShirudoUpatchLoad
	bpmShirudoUpatchLoad = func(ctx context.Context, upatchPath string, configPaths []string, stdout io.Writer, stderr io.Writer) error {
		loaded = append(loaded, upatchPath)
		return nil
	}
	t.Cleanup(func() {
		bpmShirudoUpatchLoad = oldLoad
	})

	installRoot := t.TempDir()
	installDir, err := installBPMPackage(context.Background(), "oci://registry.test/isovalent-dev/hello-bee-world:0.1.0", installRoot, nil, httpClient, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("installBPMPackage() error = %v", err)
	}
	if !strings.HasSuffix(installDir, filepath.Join("hello-bee-world-0.1.0")) {
		t.Fatalf("installDir = %q", installDir)
	}
	if len(loaded) != 1 {
		t.Fatalf("len(loaded) = %d, want 1", len(loaded))
	}
}

func TestInstallBPMPackageReadsLocalPackageFile(t *testing.T) {
	body := buildTestBPMPackageBodyWithUpatch(t)
	packagePath := filepath.Join(t.TempDir(), "hello-bee-world-0.1.0.bee")
	if err := os.WriteFile(packagePath, body, 0o600); err != nil {
		t.Fatalf("write package: %v", err)
	}

	var loaded []string
	oldLoad := bpmShirudoUpatchLoad
	bpmShirudoUpatchLoad = func(ctx context.Context, upatchPath string, configPaths []string, stdout io.Writer, stderr io.Writer) error {
		loaded = append(loaded, upatchPath)
		return nil
	}
	t.Cleanup(func() {
		bpmShirudoUpatchLoad = oldLoad
	})

	installRoot := t.TempDir()
	installDir, err := installBPMPackage(context.Background(), packagePath, installRoot, nil, nil, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("installBPMPackage() error = %v", err)
	}
	if !strings.HasSuffix(installDir, filepath.Join("hello-bee-world-0.1.0")) {
		t.Fatalf("installDir = %q", installDir)
	}
	if len(loaded) != 1 {
		t.Fatalf("len(loaded) = %d, want 1", len(loaded))
	}
}

func TestInstallBPMPackageArchiveRejectsTraversal(t *testing.T) {
	body := buildTestBPMPackageBody(t, map[string]string{
		"hello-bee-world-0.1.0/":               "",
		"hello-bee-world-0.1.0/Beefile":        "[package]\nname = \"hello-bee-world\"\n",
		"hello-bee-world-0.1.0/../outside.txt": "outside\n",
	})

	_, err := installBPMPackageArchive(context.Background(), body, t.TempDir(), nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatalf("installBPMPackageArchive() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("error = %v", err)
	}
}

func TestDefaultBPMInstallRoot(t *testing.T) {
	oldHome := bpmUserHomeDir
	bpmUserHomeDir = func() (string, error) {
		return "/home/example", nil
	}
	t.Cleanup(func() {
		bpmUserHomeDir = oldHome
	})

	root, err := defaultBPMInstallRoot()
	if err != nil {
		t.Fatalf("defaultBPMInstallRoot() error = %v", err)
	}
	if root != filepath.Join("/home/example", ".bpm") {
		t.Fatalf("root = %q", root)
	}
}

func TestDefaultBPMInstallRootRejectsMissingHome(t *testing.T) {
	oldHome := bpmUserHomeDir
	bpmUserHomeDir = func() (string, error) {
		return "", errors.New("no home")
	}
	t.Cleanup(func() {
		bpmUserHomeDir = oldHome
	})

	_, err := defaultBPMInstallRoot()
	if err == nil {
		t.Fatalf("defaultBPMInstallRoot() error = nil, want error")
	}
}

func buildTestBPMPackageBodyWithUpatch(t *testing.T) []byte {
	t.Helper()

	return buildTestBPMPackageBodyWithUpatchVersion(t, "0.1.0")
}

func buildTestBPMPackageBodyWithUpatchVersion(t *testing.T, version string) []byte {
	t.Helper()

	outputPath, err := buildBPMPackage(t.TempDir(), testBPMBuildFileWithUpatch(), bpmPackageMetadata{
		Name: "hello-bee-world",
	}, version, bpmPackageFile{
		Target: "src/hello-userns-counter.bpf.c",
		Body:   []byte("int main(void) { return 0; }\n"),
	}, bpmPackageFile{
		Target: "upatches/hello-userns-counter.upatch",
		Body:   []byte("upatch\n"),
		Upatch: true,
	}, bpmPackageFile{
		Target: "upatches/hello-userns-counter.unload.upatch",
		Body:   []byte("unload\n"),
		Upatch: true,
	})
	if err != nil {
		t.Fatalf("buildBPMPackage() error = %v", err)
	}

	body, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	return body
}

func buildTestBPMPackageBodyWithConfig(t *testing.T, config []byte) []byte {
	t.Helper()

	outputPath, err := buildBPMPackage(t.TempDir(), testBPMBuildFileWithUpatch(), bpmPackageMetadata{
		Name: "hello-bee-world",
	}, "0.1.0", bpmPackageFile{
		Target: "config.toml",
		Body:   config,
	}, bpmPackageFile{
		Target: "upatches/hello-userns-counter.upatch",
		Body:   []byte("upatch\n"),
		Upatch: true,
	}, bpmPackageFile{
		Target: "upatches/hello-userns-counter.unload.upatch",
		Body:   []byte("unload\n"),
		Upatch: true,
	})
	if err != nil {
		t.Fatalf("buildBPMPackage() error = %v", err)
	}

	body, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	return body
}

func installFakeBPMShirudo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	shirudoPath := filepath.Join(dir, "shirudo")
	body := []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$BPM_FAKE_SHIRUDO_ARGS\"\n")
	if err := os.WriteFile(shirudoPath, body, 0o755); err != nil {
		t.Fatalf("write fake shirudo: %v", err)
	}
	t.Setenv("BPM_FAKE_SHIRUDO_ARGS", argsPath)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return argsPath
}

func buildTestBPMPackageBody(t *testing.T, entries map[string]string) []byte {
	t.Helper()

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, body := range entries {
		header := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}
		if strings.HasSuffix(name, "/") {
			header.Typeflag = tar.TypeDir
			header.Mode = 0o755
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if header.Typeflag != tar.TypeDir {
			if _, err := tarWriter.Write([]byte(body)); err != nil {
				t.Fatalf("write tar body: %v", err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	return buffer.Bytes()
}
