package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestStandaloneBPMCommandRegistered(t *testing.T) {
	command := NewBPMCommand()
	if command.CommandPath() != "bpm" {
		t.Fatalf("CommandPath() = %q, want bpm", command.CommandPath())
	}

	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"pull"}, want: "bpm pull"},
		{args: []string{"push"}, want: "bpm push"},
		{args: []string{"info"}, want: "bpm info"},
		{args: []string{"key"}, want: "bpm key"},
		{args: []string{"key", "add"}, want: "bpm key add"},
		{args: []string{"key", "fingerprint"}, want: "bpm key fingerprint"},
		{args: []string{"key", "list"}, want: "bpm key list"},
		{args: []string{"install"}, want: "bpm install"},
		{args: []string{"list"}, want: "bpm list"},
		{args: []string{"uninstall"}, want: "bpm uninstall"},
		{args: []string{"version"}, want: "bpm version"},
		{args: []string{"build"}, want: "bpm build"},
	}

	for _, test := range tests {
		cmd, _, err := command.Find(test.args)
		if err != nil {
			t.Fatalf("Find(%v) error = %v", test.args, err)
		}
		if cmd.CommandPath() != test.want {
			t.Fatalf("Find(%v) = %q, want %q", test.args, cmd.CommandPath(), test.want)
		}
	}
}

func TestStandaloneBPMOldTransferCommandsRejected(t *testing.T) {
	for _, args := range [][]string{
		{"get"},
		{"put"},
	} {
		command := NewBPMCommand()
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&output)
		command.SetArgs(args)

		if err := command.Execute(); err == nil {
			t.Fatalf("Execute(%v) error = nil, want unknown command error", args)
		}
	}
}

func TestStandaloneBPMCommandPrintsHelpWithoutArgs(t *testing.T) {
	command := NewBPMCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"An eBPF Package Manager",
		"Usage:",
		"Available Commands:",
		"build",
		"info",
		"install",
		"key",
		"pull",
		"push",
		"version",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("help output missing %q:\n%s", want, got)
		}
	}
	for _, removed := range []string{
		"--concurrency",
		"--timeout",
	} {
		if strings.Contains(got, removed) {
			t.Fatalf("help output unexpectedly contains %q:\n%s", removed, got)
		}
	}
}

func TestStandaloneBPMCommandHasNoRuntimeFlags(t *testing.T) {
	command := NewBPMCommand()
	for _, name := range []string{"concurrency", "timeout"} {
		if command.PersistentFlags().Lookup(name) != nil {
			t.Fatalf("persistent flag %q found", name)
		}
		if command.Flags().Lookup(name) != nil {
			t.Fatalf("flag %q found", name)
		}
	}
}

func TestStandaloneBPMInstallPassesConfigFilesInOrder(t *testing.T) {
	oldInstallPackage := bpmStandaloneInstallPackage
	called := false
	bpmStandaloneInstallPackage = func(ctx context.Context, rawReference string, installRoot string, configPaths []string, httpClient *http.Client, stdout io.Writer, stderr io.Writer) (string, error) {
		called = true
		if rawReference != "hello-bee-world-0.1.0.bee" {
			t.Fatalf("rawReference = %q", rawReference)
		}
		if installRoot != "" {
			t.Fatalf("installRoot = %q", installRoot)
		}
		wantConfigPaths := []string{"first.toml", "second.toml"}
		if !reflect.DeepEqual(configPaths, wantConfigPaths) {
			t.Fatalf("configPaths = %#v, want %#v", configPaths, wantConfigPaths)
		}
		if httpClient != nil {
			t.Fatalf("httpClient = %#v, want nil", httpClient)
		}
		return "/tmp/hello-bee-world-0.1.0", nil
	}
	t.Cleanup(func() {
		bpmStandaloneInstallPackage = oldInstallPackage
	})

	command := NewBPMCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"install", "-f", "first.toml", "-f", "second.toml", "hello-bee-world-0.1.0.bee"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !called {
		t.Fatalf("bpmStandaloneInstallPackage was not called")
	}
	if got := output.String(); got != "/tmp/hello-bee-world-0.1.0\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestStandaloneBPMListHasNoConfigFlag(t *testing.T) {
	command := NewBPMCommand()
	list, _, err := command.Find([]string{"list"})
	if err != nil {
		t.Fatalf("Find(list) error = %v", err)
	}
	if list.Flags().Lookup("config") != nil {
		t.Fatalf("list --config flag found")
	}
}

func TestStandaloneBPMHelpUsesEBPF(t *testing.T) {
	standaloneBPF := regexp.MustCompile(`\bBPF\b`)
	for _, args := range [][]string{
		{},
		{"build", "--help"},
		{"info", "--help"},
		{"install", "--help"},
		{"key", "--help"},
		{"key", "add", "--help"},
		{"key", "fingerprint", "--help"},
		{"key", "list", "--help"},
		{"list", "--help"},
		{"pull", "--help"},
		{"push", "--help"},
		{"uninstall", "--help"},
		{"version", "--help"},
	} {
		command := NewBPMCommand()
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&output)
		command.SetArgs(args)

		if err := command.Execute(); err != nil {
			t.Fatalf("Execute(%v) error = %v", args, err)
		}
		got := output.String()
		if !strings.Contains(got, "eBPF") {
			t.Fatalf("help output for %v missing eBPF:\n%s", args, got)
		}
		if standaloneBPF.MatchString(got) {
			t.Fatalf("help output for %v contains standalone BPF:\n%s", args, got)
		}
	}
}

func TestStandaloneBPMInfoHelpIncludesExamples(t *testing.T) {
	command := NewBPMCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"info", "--help"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute(info --help) error = %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"Examples:",
		"bpm info ./hello-bee-world-0.0.7.bee",
		"bpm info oci://quay.io/isovalent-dev/hello-bee-world:0.0.7",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("info help missing %q:\n%s", want, got)
		}
	}
}

func TestStandaloneBPMKeyFingerprintHelpIncludesExamples(t *testing.T) {
	command := NewBPMCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"key", "fingerprint", "--help"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute(key fingerprint --help) error = %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"Examples:",
		"bpm key fingerprint ./hello-bee-world-0.0.7.bee",
		"bpm key fingerprint oci://quay.io/isovalent-dev/hello-bee-world:0.0.7",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("key fingerprint help missing %q:\n%s", want, got)
		}
	}
}

func TestStandaloneBPMKeyAddHelpIncludesExamples(t *testing.T) {
	command := NewBPMCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"key", "add", "--help"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute(key add --help) error = %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"Examples:",
		"bpm key add ./hello-bee-world-0.0.7.bee",
		"bpm key add oci://quay.io/isovalent-dev/hello-bee-world:0.0.7",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("key add help missing %q:\n%s", want, got)
		}
	}
}

func TestStandaloneBPMBuildFlags(t *testing.T) {
	command := NewBPMCommand()
	build, _, err := command.Find([]string{"build"})
	if err != nil {
		t.Fatalf("Find(build) error = %v", err)
	}

	keysDir := build.Flags().Lookup("keys-dir")
	if keysDir == nil {
		t.Fatalf("keys-dir flag not found")
	}
	if keysDir.DefValue != defaultBPMBuildKeysDir {
		t.Fatalf("keys-dir default = %q, want %q", keysDir.DefValue, defaultBPMBuildKeysDir)
	}
}

func TestStandaloneBPMVersionPrintsVersion(t *testing.T) {
	oldVersion := version
	version = "1.2.3-test"
	t.Cleanup(func() {
		version = oldVersion
	})

	command := NewBPMCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"version"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := strings.TrimSpace(output.String()); got != "1.2.3-test" {
		t.Fatalf("output = %q, want %q", got, "1.2.3-test")
	}
}

func TestStandaloneBPMPullIsQuietOnSuccess(t *testing.T) {
	oldGetPackage := bpmStandaloneGetPackage
	called := false
	bpmStandaloneGetPackage = func(ctx context.Context, rawReference string, outputDir string, httpClient *http.Client) (string, error) {
		called = true
		if rawReference != "oci://quay.io/isovalent-dev/hello-bee-world:0.0.7" {
			t.Fatalf("rawReference = %q", rawReference)
		}
		if outputDir != "." {
			t.Fatalf("outputDir = %q", outputDir)
		}
		if httpClient != nil {
			t.Fatalf("httpClient = %#v, want nil", httpClient)
		}
		return "hello-bee-world-0.0.7.bee", nil
	}
	t.Cleanup(func() {
		bpmStandaloneGetPackage = oldGetPackage
	})

	command := NewBPMCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"pull", "oci://quay.io/isovalent-dev/hello-bee-world:0.0.7"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !called {
		t.Fatalf("bpmStandaloneGetPackage was not called")
	}
	if got := output.String(); got != "" {
		t.Fatalf("output = %q, want empty", got)
	}
}

func TestStandaloneBPMInfoPrintsReadme(t *testing.T) {
	want := "# hello-bee-world\n\nHello from README.\n"
	packagePath := buildTestBPMPackageWithReadme(t, want)

	command := NewBPMCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"info", packagePath})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestStandaloneBPMKeyFingerprintPrintsSPKIFingerprint(t *testing.T) {
	packagePath, certificate := buildTestBPMPackageWithCert(t)
	want, err := bpmSPKISHA256Fingerprint(certificate)
	if err != nil {
		t.Fatalf("bpmSPKISHA256Fingerprint() error = %v", err)
	}

	command := NewBPMCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"key", "fingerprint", packagePath})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := strings.TrimSpace(output.String()); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}
