package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultBPMBuildFile(t *testing.T) {
	if defaultBPMBuildFile != "Beefile" {
		t.Fatalf("defaultBPMBuildFile = %q, want Beefile", defaultBPMBuildFile)
	}
}

func TestDefaultBPMBuildKeysDir(t *testing.T) {
	if defaultBPMBuildKeysDir != "~/.config/bpm/" {
		t.Fatalf("defaultBPMBuildKeysDir = %q, want ~/.config/bpm/", defaultBPMBuildKeysDir)
	}
}

func TestResolveBPMBuildKeysDirDefault(t *testing.T) {
	oldHome := bpmUserHomeDir
	bpmUserHomeDir = func() (string, error) {
		return "/home/example", nil
	}
	t.Cleanup(func() {
		bpmUserHomeDir = oldHome
	})

	path, err := resolveBPMBuildKeysDir("")
	if err != nil {
		t.Fatalf("resolveBPMBuildKeysDir() error = %v", err)
	}
	want := filepath.Join("/home/example", ".config", "bpm")
	if path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
}

func TestResolveBPMBuildKeysDirExplicitPath(t *testing.T) {
	path, err := resolveBPMBuildKeysDir("/tmp/bpm-keys")
	if err != nil {
		t.Fatalf("resolveBPMBuildKeysDir() error = %v", err)
	}
	if path != filepath.Clean("/tmp/bpm-keys") {
		t.Fatalf("path = %q", path)
	}
}

func TestResolveBPMBuildFilePathDefaultContext(t *testing.T) {
	path, err := resolveBPMBuildFilePath(".", "ignored", false)
	if err != nil {
		t.Fatalf("resolveBPMBuildFilePath() error = %v", err)
	}
	if path != defaultBPMBuildFile {
		t.Fatalf("path = %q, want %q", path, defaultBPMBuildFile)
	}
}

func TestResolveBPMBuildFilePathContext(t *testing.T) {
	path, err := resolveBPMBuildFilePath("examples/hello-bee-world", "ignored", false)
	if err != nil {
		t.Fatalf("resolveBPMBuildFilePath() error = %v", err)
	}
	want := filepath.Join("examples", "hello-bee-world", defaultBPMBuildFile)
	if path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
}

func TestResolveBPMBuildFilePathExplicitFile(t *testing.T) {
	path, err := resolveBPMBuildFilePath("examples/hello-bee-world", "CustomBeefile", true)
	if err != nil {
		t.Fatalf("resolveBPMBuildFilePath() error = %v", err)
	}
	if path != "CustomBeefile" {
		t.Fatalf("path = %q, want CustomBeefile", path)
	}
}

func TestResolveBPMBuildFilePathRejectsEmptyContext(t *testing.T) {
	_, err := resolveBPMBuildFilePath(" ", "ignored", false)
	if err == nil {
		t.Fatalf("resolveBPMBuildFilePath() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "build context is empty") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateBPMBuildFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Beefile")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write Beefile: %v", err)
	}

	if err := validateBPMBuildFile(path); err != nil {
		t.Fatalf("validateBPMBuildFile() error = %v", err)
	}
}

func TestValidateBPMBuildFileRejectsMissingFile(t *testing.T) {
	err := validateBPMBuildFile(filepath.Join(t.TempDir(), "Beefile"))
	if err == nil {
		t.Fatalf("validateBPMBuildFile() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "read build file") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateBPMBuildFileRejectsDirectory(t *testing.T) {
	err := validateBPMBuildFile(t.TempDir())
	if err == nil {
		t.Fatalf("validateBPMBuildFile() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("error = %v", err)
	}
}
