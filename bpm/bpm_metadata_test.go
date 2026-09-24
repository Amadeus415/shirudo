package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBPMBuildMetadata(t *testing.T) {
	metadata, err := parseBPMBuildMetadata([]byte(`
[package]
name = "xdp-drop"
description = "Drop selected packets"
license = "Apache-2.0"
authors = ["Jane Example <jane@example.com>", 'BPF Team']
`))
	if err != nil {
		t.Fatalf("parseBPMBuildMetadata() error = %v", err)
	}
	if metadata.Name != "xdp-drop" {
		t.Fatalf("Name = %q", metadata.Name)
	}
	if metadata.Description != "Drop selected packets" {
		t.Fatalf("Description = %q", metadata.Description)
	}
	if metadata.License != "Apache-2.0" {
		t.Fatalf("License = %q", metadata.License)
	}
	if len(metadata.Authors) != 2 || metadata.Authors[0] != "Jane Example <jane@example.com>" || metadata.Authors[1] != "BPF Team" {
		t.Fatalf("Authors = %#v", metadata.Authors)
	}
}

func TestParseBPMBuildSpecFiles(t *testing.T) {
	spec, err := parseBPMBuildSpec([]byte(`
[package]
name = "hello-bee-world"

[[files]]
source = "hello.txt"
target = "share/hello.txt"

[[files]]
source = "LICENSE"
`))
	if err != nil {
		t.Fatalf("parseBPMBuildSpec() error = %v", err)
	}
	if spec.Metadata.Name != "hello-bee-world" {
		t.Fatalf("Name = %q", spec.Metadata.Name)
	}
	if len(spec.Files) != 2 {
		t.Fatalf("len(Files) = %d, want 2", len(spec.Files))
	}
	if spec.Files[0].Source != "hello.txt" || spec.Files[0].Target != "share/hello.txt" {
		t.Fatalf("Files[0] = %#v", spec.Files[0])
	}
	if spec.Files[1].Source != "LICENSE" || spec.Files[1].Target != "LICENSE" {
		t.Fatalf("Files[1] = %#v", spec.Files[1])
	}
}

func TestParseBPMBuildSpecUpatches(t *testing.T) {
	spec, err := parseBPMBuildSpec([]byte(`
[package]
name = "hello-bee-world"

[[upatches]]
source = "hello-userns-counter.bpf.c"
load_target = "upatches/userns.upatch"
unload_target = "upatches/userns.unload.upatch"

[[upatches]]
source = "nested/hello-sched-counter.bpf.c"

[[upatches]]
type = "java"
source = "agent.jar"
telemetry_upatch = "javaagent_metrics"
`))
	if err != nil {
		t.Fatalf("parseBPMBuildSpec() error = %v", err)
	}
	if len(spec.Upatches) != 3 {
		t.Fatalf("len(Upatches) = %d, want 3", len(spec.Upatches))
	}
	if spec.Upatches[0].Source != "hello-userns-counter.bpf.c" || spec.Upatches[0].LoadTarget != "upatches/userns.upatch" ||
		spec.Upatches[0].UnloadTarget != "upatches/userns.unload.upatch" {
		t.Fatalf("Upatches[0] = %#v", spec.Upatches[0])
	}
	if spec.Upatches[1].Source != "nested/hello-sched-counter.bpf.c" || spec.Upatches[1].LoadTarget != "upatches/hello-sched-counter.upatch" ||
		spec.Upatches[1].UnloadTarget != "upatches/hello-sched-counter.unload.upatch" {
		t.Fatalf("Upatches[1] = %#v", spec.Upatches[1])
	}
	if spec.Upatches[2].Type != "java" || spec.Upatches[2].Source != "agent.jar" ||
		spec.Upatches[2].TelemetryUpatch != "javaagent_metrics" ||
		spec.Upatches[2].LoadTarget != "upatches/agent.upatch" ||
		spec.Upatches[2].UnloadTarget != "upatches/agent.unload.upatch" {
		t.Fatalf("Upatches[2] = %#v", spec.Upatches[2])
	}
}

func TestParseBPMBuildSpecUpatchTreeMetadataKeepsMultipleEntries(t *testing.T) {
	spec, err := parseBPMBuildSpec([]byte(`
[package]
name = "tree-package"

[[upatches]]
source = "block-afalg.bpf.c"

[upatches.tree]
id = "block-afalg"
load_artifact = "upatches/block-afalg.upatch"
unload_artifact = "upatches/block-afalg.unload.upatch"

[upatches.tree.selector]
kernel_release_prefix = ["6.16", "6.18"]
kernel_build_id = ["deadbeef"]
architecture = ["x86_64", "aarch64"]

[upatches.tree.selector.kconfig]
CONFIG_BPF = ["y", "m"]

[upatches.tree.selector.labels]
env = ["prod", "staging"]

[[upatches]]
source = "second.bpf.c"

[upatches.tree]
id = "second"
load_artifact = "upatches/second.upatch"
unload_artifact = "upatches/second.unload.upatch"
future_field = { enabled = true }
`))
	if err != nil {
		t.Fatalf("parseBPMBuildSpec() error = %v", err)
	}
	if len(spec.Upatches) != 2 || spec.Upatches[0].Tree == nil || spec.Upatches[1].Tree == nil {
		t.Fatalf("Upatches = %#v, want two tree-enabled entries", spec.Upatches)
	}
	first := spec.Upatches[0].Tree
	if first.ID != "block-afalg" || first.LoadArtifact != "upatches/block-afalg.upatch" ||
		len(first.Selector.KernelReleasePrefix) != 2 ||
		first.Selector.KernelReleasePrefix[0] != "6.16" ||
		first.Selector.KernelReleasePrefix[1] != "6.18" ||
		len(first.Selector.KernelBuildID) != 1 ||
		first.Selector.KernelBuildID[0] != "deadbeef" ||
		len(first.Selector.Architecture) != 2 ||
		first.Selector.Architecture[0] != "x86_64" ||
		first.Selector.Architecture[1] != "aarch64" ||
		len(first.Selector.Kconfig["CONFIG_BPF"]) != 2 ||
		first.Selector.Kconfig["CONFIG_BPF"][0] != "y" ||
		first.Selector.Kconfig["CONFIG_BPF"][1] != "m" ||
		len(first.Selector.Labels["env"]) != 2 ||
		first.Selector.Labels["env"][0] != "prod" ||
		first.Selector.Labels["env"][1] != "staging" {
		t.Fatalf("first tree metadata = %#v", first)
	}
	if spec.Upatches[1].Tree.ID != "second" {
		t.Fatalf("second tree metadata = %#v", spec.Upatches[1].Tree)
	}
}

func TestLoadBPMBuildSpecSetsScopeDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Beefile")
	if err := os.WriteFile(path, []byte(`
[package]
name = "hello-bee-world"
`), 0o600); err != nil {
		t.Fatalf("write Beefile: %v", err)
	}

	spec, err := loadBPMBuildSpec(path)
	if err != nil {
		t.Fatalf("loadBPMBuildSpec() error = %v", err)
	}
	if spec.ScopeDir != dir {
		t.Fatalf("ScopeDir = %q, want %q", spec.ScopeDir, dir)
	}
}

func TestResolveBPMBuildFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write hello.txt: %v", err)
	}

	files, err := resolveBPMBuildFiles(dir, []bpmBuildFileEntry{{
		Source: "hello.txt",
		Target: "share/hello.txt",
	}})
	if err != nil {
		t.Fatalf("resolveBPMBuildFiles() error = %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("len(files) = %d, want 1", len(files))
	}
	if files[0].Target != "share/hello.txt" {
		t.Fatalf("Target = %q", files[0].Target)
	}
	if string(files[0].Body) != "hello\n" {
		t.Fatalf("Body = %q", files[0].Body)
	}
}

func TestResolveBPMBuildPackageFilesIncludesUpatches(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write hello.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hello.upatch"), []byte("upatch\n"), 0o600); err != nil {
		t.Fatalf("write hello.upatch: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hello.unload.upatch"), []byte("unload\n"), 0o600); err != nil {
		t.Fatalf("write hello.unload.upatch: %v", err)
	}

	files, err := resolveBPMBuildPackageFiles(dir, []bpmBuildFileEntry{{
		Source: "hello.txt",
		Target: "share/hello.txt",
	}}, []bpmBuildUpatchEntry{{
		Source:       "hello.bpf.c",
		LoadTarget:   "upatches/hello.upatch",
		UnloadTarget: "upatches/hello.unload.upatch",
	}})
	if err != nil {
		t.Fatalf("resolveBPMBuildPackageFiles() error = %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("len(files) = %d, want 3", len(files))
	}
	if files[0].Upatch {
		t.Fatalf("files[0].Upatch = true, want false")
	}
	if !files[1].Upatch {
		t.Fatalf("files[1].Upatch = false, want true")
	}
	if files[1].Target != "upatches/hello.upatch" || string(files[1].Body) != "upatch\n" {
		t.Fatalf("files[1] = %#v", files[1])
	}
	if !files[2].Upatch {
		t.Fatalf("files[2].Upatch = false, want true")
	}
	if files[2].Target != "upatches/hello.unload.upatch" || string(files[2].Body) != "unload\n" {
		t.Fatalf("files[2] = %#v", files[2])
	}
}

func TestResolveBPMBuildPackageFilesRejectsDuplicateTargets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write hello.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hello.upatch"), []byte("upatch\n"), 0o600); err != nil {
		t.Fatalf("write hello.upatch: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hello.unload.upatch"), []byte("unload\n"), 0o600); err != nil {
		t.Fatalf("write hello.unload.upatch: %v", err)
	}

	_, err := resolveBPMBuildPackageFiles(dir, []bpmBuildFileEntry{{
		Source: "hello.txt",
		Target: "same",
	}}, []bpmBuildUpatchEntry{{
		Source:       "hello.bpf.c",
		LoadTarget:   "same",
		UnloadTarget: "upatches/hello.unload.upatch",
	}})
	if err == nil {
		t.Fatalf("resolveBPMBuildPackageFiles() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "duplicated or reserved") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveBPMBuildFilesRejectsParentSource(t *testing.T) {
	_, err := resolveBPMBuildFiles(t.TempDir(), []bpmBuildFileEntry{{
		Source: "../outside.txt",
		Target: "outside.txt",
	}})
	if err == nil {
		t.Fatalf("resolveBPMBuildFiles() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "escapes the Beefile directory") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveBPMBuildFilesRejectsSymlinkOutsideScope(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "outside-link.txt")); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	_, err := resolveBPMBuildFiles(dir, []bpmBuildFileEntry{{
		Source: "outside-link.txt",
		Target: "outside.txt",
	}})
	if err == nil {
		t.Fatalf("resolveBPMBuildFiles() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "escapes the Beefile directory") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveBPMBuildFilesRejectsUnsafeTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write hello.txt: %v", err)
	}

	_, err := resolveBPMBuildFiles(dir, []bpmBuildFileEntry{{
		Source: "hello.txt",
		Target: "../hello.txt",
	}})
	if err == nil {
		t.Fatalf("resolveBPMBuildFiles() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "escapes the package directory") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveBPMBuildFilesRejectsReservedRootTargets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write hello.txt: %v", err)
	}

	for _, target := range []string{defaultBPMBuildFile, defaultBPMReadmeFile} {
		_, err := resolveBPMBuildFiles(dir, []bpmBuildFileEntry{{
			Source: "hello.txt",
			Target: target,
		}})
		if err == nil {
			t.Fatalf("resolveBPMBuildFiles(target %q) error = nil, want error", target)
		}
		if !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("target %q error = %v", target, err)
		}
	}
}

func TestParseBPMBuildMetadataAllowsFutureInstructions(t *testing.T) {
	metadata, err := parseBPMBuildMetadata([]byte(`
[package]
name = "xdp-drop"

FROM clang
`))
	if err != nil {
		t.Fatalf("parseBPMBuildMetadata() error = %v", err)
	}
	if metadata.Name != "xdp-drop" {
		t.Fatalf("Name = %q", metadata.Name)
	}
}

func TestLoadBPMBuildMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Beefile")
	if err := os.WriteFile(path, []byte(`
[package]
name = "trace-open"
`), 0o600); err != nil {
		t.Fatalf("write Beefile: %v", err)
	}

	metadata, err := loadBPMBuildMetadata(path)
	if err != nil {
		t.Fatalf("loadBPMBuildMetadata() error = %v", err)
	}
	if metadata.Name != "trace-open" {
		t.Fatalf("Name = %q", metadata.Name)
	}
}

func TestParseBPMBuildMetadataRejectsMissingPackage(t *testing.T) {
	_, err := parseBPMBuildMetadata([]byte(`name = "xdp-drop"`))
	if err == nil {
		t.Fatalf("parseBPMBuildMetadata() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "missing [package]") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseBPMBuildMetadataRejectsMissingName(t *testing.T) {
	_, err := parseBPMBuildMetadata([]byte(`
[package]
description = "Drop selected packets"
`))
	if err == nil {
		t.Fatalf("parseBPMBuildMetadata() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "package.name is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseBPMBuildMetadataRejectsVersionField(t *testing.T) {
	_, err := parseBPMBuildMetadata([]byte(`
[package]
name = "xdp-drop"
version = "0.1.0"
`))
	if err == nil {
		t.Fatalf("parseBPMBuildMetadata() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "unknown package field") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseBPMBuildMetadataRejectsUnknownPackageField(t *testing.T) {
	_, err := parseBPMBuildMetadata([]byte(`
[package]
name = "xdp-drop"
website = "https://example.com"
`))
	if err == nil {
		t.Fatalf("parseBPMBuildMetadata() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "unknown package field") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseBPMBuildMetadataRejectsInvalidAuthors(t *testing.T) {
	_, err := parseBPMBuildMetadata([]byte(`
[package]
name = "xdp-drop"
authors = "Jane"
`))
	if err == nil {
		t.Fatalf("parseBPMBuildMetadata() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "must be a string array") {
		t.Fatalf("error = %v", err)
	}
}
