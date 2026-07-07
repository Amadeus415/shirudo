package main

import (
	"path/filepath"
	"testing"
)

func TestLoadBPMPackageArchive(t *testing.T) {
	outputDir := t.TempDir()
	outputPath, err := buildBPMPackage(outputDir, testBPMBuildFile(), bpmPackageMetadata{
		Name:        "hello-bee-world",
		Description: "Minimal hello-bee-world BPF package example",
		License:     "Apache-2.0",
		Authors:     []string{"Isovalent"},
	}, "0.1.0")
	if err != nil {
		t.Fatalf("buildBPMPackage() error = %v", err)
	}

	archive, err := loadBPMPackageArchive(outputPath)
	if err != nil {
		t.Fatalf("loadBPMPackageArchive() error = %v", err)
	}
	if len(archive.Body) == 0 {
		t.Fatalf("archive body is empty")
	}
	if archive.Metadata.Name != "hello-bee-world" {
		t.Fatalf("Name = %q", archive.Metadata.Name)
	}
	if archive.Metadata.Version != "0.1.0" {
		t.Fatalf("Version = %q", archive.Metadata.Version)
	}
	if archive.Metadata.Description != "Minimal hello-bee-world BPF package example" {
		t.Fatalf("Description = %q", archive.Metadata.Description)
	}
}

func TestLoadBPMPackageArchiveReadsUpatches(t *testing.T) {
	outputDir := t.TempDir()
	outputPath, err := buildBPMPackage(outputDir, testBPMBuildFileWithUpatch(), bpmPackageMetadata{
		Name: "hello-bee-world",
	}, "0.1.0", bpmPackageFile{
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

	archive, err := loadBPMPackageArchive(outputPath)
	if err != nil {
		t.Fatalf("loadBPMPackageArchive() error = %v", err)
	}
	if len(archive.Metadata.Upatches) != 1 {
		t.Fatalf("len(Upatches) = %d, want 1", len(archive.Metadata.Upatches))
	}
	if archive.Metadata.Upatches[0].LoadPath != "upatches/hello-userns-counter.upatch" ||
		archive.Metadata.Upatches[0].UnloadPath != "upatches/hello-userns-counter.unload.upatch" {
		t.Fatalf("Upatches[0] = %#v", archive.Metadata.Upatches[0])
	}
}

func TestReadBPMPackageReadme(t *testing.T) {
	want := "# hello-bee-world\n\nHello from README.\n"
	outputPath := buildTestBPMPackageWithReadme(t, want)

	archive, err := loadBPMPackageArchive(outputPath)
	if err != nil {
		t.Fatalf("loadBPMPackageArchive() error = %v", err)
	}
	got, ok, err := readBPMPackageReadme(archive.Body)
	if err != nil {
		t.Fatalf("readBPMPackageReadme() error = %v", err)
	}
	if !ok {
		t.Fatalf("readBPMPackageReadme() ok = false")
	}
	if string(got) != want {
		t.Fatalf("README = %q, want %q", got, want)
	}
}

func TestLoadBPMPackageArchiveRejectsMissingFile(t *testing.T) {
	_, err := loadBPMPackageArchive(filepath.Join(t.TempDir(), "missing.bee"))
	if err == nil {
		t.Fatalf("loadBPMPackageArchive() error = nil, want error")
	}
}
