package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildBPMPackage(t *testing.T) {
	outputDir := t.TempDir()
	buildFile := testBPMBuildFile()
	outputPath, err := buildBPMPackage(outputDir, buildFile, bpmPackageMetadata{
		Name:        "hello-bee-world",
		Description: "Minimal hello-bee-world BPF package example",
		License:     "Apache-2.0",
		Authors:     []string{"Isovalent"},
	}, "0.1.0")
	if err != nil {
		t.Fatalf("buildBPMPackage() error = %v", err)
	}

	wantPath := filepath.Join(outputDir, "hello-bee-world-0.1.0.bee")
	if outputPath != wantPath {
		t.Fatalf("outputPath = %q, want %q", outputPath, wantPath)
	}

	entries := readBPMPackageEntries(t, outputPath)
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].Name != "hello-bee-world-0.1.0/" {
		t.Fatalf("entries[0].Name = %q", entries[0].Name)
	}
	if entries[1].Name != "hello-bee-world-0.1.0/Beefile" {
		t.Fatalf("entries[1].Name = %q", entries[1].Name)
	}
	if entries[1].Body != string(buildFile) {
		t.Fatalf("Beefile = %q, want %q", entries[1].Body, buildFile)
	}
	if strings.Contains(entries[1].Body, `version = "0.1.0"`) {
		t.Fatalf("Beefile unexpectedly contains generated version: %q", entries[1].Body)
	}
}

func TestBuildBPMPackageIncludesFiles(t *testing.T) {
	outputDir := t.TempDir()
	outputPath, err := buildBPMPackage(outputDir, testBPMBuildFile(), bpmPackageMetadata{
		Name: "hello-bee-world",
	}, "0.1.0", bpmPackageFile{
		Target: "share/hello.txt",
		Body:   []byte("Hello, bee world.\n"),
		Mode:   0o600,
	})
	if err != nil {
		t.Fatalf("buildBPMPackage() error = %v", err)
	}

	entries := readBPMPackageEntries(t, outputPath)
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(entries))
	}
	if entries[2].Name != "hello-bee-world-0.1.0/share/hello.txt" {
		t.Fatalf("entries[2].Name = %q", entries[2].Name)
	}
	if entries[2].Body != "Hello, bee world.\n" {
		t.Fatalf("entries[2].Body = %q", entries[2].Body)
	}
}

func TestBuildBPMPackageIncludesUpatchesAndBeefile(t *testing.T) {
	outputDir := t.TempDir()
	outputPath, err := buildBPMPackage(outputDir, testBPMBuildFileWithUpatch(), bpmPackageMetadata{
		Name: "hello-bee-world",
	}, "0.1.0", bpmPackageFile{
		Target: "upatches/hello-userns-counter.upatch",
		Body:   []byte("upatch\n"),
		Mode:   0o600,
		Upatch: true,
	}, bpmPackageFile{
		Target: "upatches/hello-userns-counter.unload.upatch",
		Body:   []byte("unload\n"),
		Mode:   0o600,
		Upatch: true,
	})
	if err != nil {
		t.Fatalf("buildBPMPackage() error = %v", err)
	}

	entries := readBPMPackageEntries(t, outputPath)
	if len(entries) != 4 {
		t.Fatalf("len(entries) = %d, want 4", len(entries))
	}
	if !strings.Contains(entries[1].Body, "[[upatches]]") {
		t.Fatalf("Beefile = %q", entries[1].Body)
	}
	if !strings.Contains(entries[1].Body, `load_target = "upatches/hello-userns-counter.upatch"`) {
		t.Fatalf("Beefile = %q", entries[1].Body)
	}
	if !strings.Contains(entries[1].Body, `unload_target = "upatches/hello-userns-counter.unload.upatch"`) {
		t.Fatalf("Beefile = %q", entries[1].Body)
	}
	if entries[2].Name != "hello-bee-world-0.1.0/upatches/hello-userns-counter.upatch" {
		t.Fatalf("entries[2].Name = %q", entries[2].Name)
	}
	if entries[3].Name != "hello-bee-world-0.1.0/upatches/hello-userns-counter.unload.upatch" {
		t.Fatalf("entries[3].Name = %q", entries[3].Name)
	}
}

func testBPMBuildFile() []byte {
	return []byte(`[package]
name = "hello-bee-world"
description = "Minimal hello-bee-world BPF package example"
license = "Apache-2.0"
authors = ["Isovalent"]
`)
}

func testBPMBuildFileWithUpatch() []byte {
	return []byte(`[package]
name = "hello-bee-world"

[[upatches]]
source = "hello-userns-counter.bpf.c"
load_target = "upatches/hello-userns-counter.upatch"
unload_target = "upatches/hello-userns-counter.unload.upatch"
`)
}

func TestNormalizeBPMBuildVersionRejectsEmpty(t *testing.T) {
	_, err := normalizeBPMBuildVersion(" ")
	if err == nil {
		t.Fatalf("normalizeBPMBuildVersion() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "version is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestNormalizeBPMBuildVersionRejectsPathSeparator(t *testing.T) {
	_, err := normalizeBPMBuildVersion("../0.1.0")
	if err == nil {
		t.Fatalf("normalizeBPMBuildVersion() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "must contain only") {
		t.Fatalf("error = %v", err)
	}
}

type bpmPackageEntry struct {
	Name string
	Body string
}

func readBPMPackageEntries(t *testing.T, packagePath string) []bpmPackageEntry {
	t.Helper()

	file, err := os.Open(packagePath)
	if err != nil {
		t.Fatalf("open package: %v", err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("open gzip: %v", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	var entries []bpmPackageEntry
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}

		var body strings.Builder
		if header.Typeflag != tar.TypeDir {
			if _, err := io.Copy(&body, tarReader); err != nil {
				t.Fatalf("read entry body: %v", err)
			}
		}
		entries = append(entries, bpmPackageEntry{
			Name: header.Name,
			Body: body.String(),
		})
	}

	return entries
}
