package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildBPMUpatchesRunsShirudoBuildAndUnload(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.bpf.c"), []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	loadPath := filepath.Join(dir, "hello.upatch")
	unloadPath := filepath.Join(dir, "hello.unload.upatch")
	if err := os.WriteFile(loadPath, []byte("old load\n"), 0o600); err != nil {
		t.Fatalf("write old load: %v", err)
	}
	if err := os.WriteFile(unloadPath, []byte("old unload\n"), 0o600); err != nil {
		t.Fatalf("write old unload: %v", err)
	}
	wantDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	wantLoadPath := filepath.Join(wantDir, "hello.upatch")
	wantUnloadPath := filepath.Join(wantDir, "hello.unload.upatch")

	var calls []bpmShirudoBuildUpatchOptions
	oldBuild := bpmShirudoBuildUpatch
	bpmShirudoBuildUpatch = func(ctx context.Context, opts bpmShirudoBuildUpatchOptions, stdout io.Writer, stderr io.Writer) error {
		calls = append(calls, opts)
		body := testShirudoUpatchBytes(t, "hello-upatch", 0, false)
		if opts.Unload {
			body = testShirudoUpatchBytes(t, "hello-upatch", shirudoDirectiveUnload, false)
		}
		return os.WriteFile(opts.Output, body, 0o600)
	}
	t.Cleanup(func() {
		bpmShirudoBuildUpatch = oldBuild
	})

	keysDir := "/tmp/bpm-keys"
	built, err := buildBPMUpatches(context.Background(), bpmBuildSpec{
		ScopeDir: dir,
		Upatches: []bpmBuildUpatchEntry{{
			Source:       "hello.bpf.c",
			LoadTarget:   "upatches/hello.upatch",
			UnloadTarget: "upatches/hello.unload.upatch",
		}},
	}, keysDir, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("buildBPMUpatches() error = %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("len(calls) = %d, want 2", len(calls))
	}
	if calls[0].WorkDir != wantDir || calls[0].Source != "hello.bpf.c" || calls[0].Output != wantLoadPath || calls[0].Unload || calls[0].KeysDir != keysDir {
		t.Fatalf("calls[0] = %#v", calls[0])
	}
	if calls[1].WorkDir != wantDir || calls[1].Output != wantUnloadPath || !calls[1].Unload || calls[1].UnloadName != "hello-upatch" ||
		calls[1].PayloadSHA256 != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" || calls[1].KeysDir != keysDir {
		t.Fatalf("calls[1] = %#v", calls[1])
	}
	if body, err := os.ReadFile(loadPath); err != nil {
		t.Fatalf("read load: %v", err)
	} else if upatch, err := parseShirudoUpatch(body); err != nil {
		t.Fatalf("parse load: %v", err)
	} else if upatch.Directive != "load" || upatch.Name != "hello-upatch" {
		t.Fatalf("load upatch = %#v", upatch)
	}
	if body, err := os.ReadFile(unloadPath); err != nil {
		t.Fatalf("read unload: %v", err)
	} else if upatch, err := parseShirudoUpatch(body); err != nil {
		t.Fatalf("parse unload: %v", err)
	} else if upatch.Directive != "unload" || upatch.Name != "hello-upatch" {
		t.Fatalf("unload upatch = %#v", upatch)
	}
	if len(built) != 1 || built[0].LoadOutput != "hello.upatch" || built[0].UnloadOutput != "hello.unload.upatch" {
		t.Fatalf("built = %#v", built)
	}
}

func TestRunBPMShirudoBuildUpatchCommand(t *testing.T) {
	dir := t.TempDir()
	shirudo := filepath.Join(dir, "shirudo")
	logPath := filepath.Join(dir, "argv")
	if err := os.WriteFile(shirudo, []byte("#!/bin/sh\nprintf '%s\\n' \"$PWD|$*\" > \"$1.argv\"\n"), 0o700); err != nil {
		t.Fatalf("write fake shirudo: %v", err)
	}

	oldPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
	})

	if err := runBPMShirudoBuildUpatch(context.Background(), bpmShirudoBuildUpatchOptions{
		WorkDir:       dir,
		Source:        "hello.bpf.c",
		Output:        logPath,
		Unload:        true,
		UnloadName:    "hello-upatch",
		PayloadSHA256: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		KeysDir:       "/tmp/keys",
	}, io.Discard, io.Discard); err != nil {
		t.Fatalf("runBPMShirudoBuildUpatch() error = %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dir, "build.argv"))
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	got := string(body)
	if !strings.Contains(got, dir+"|build --unload hello-upatch --payload-sha256 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f -o "+logPath+" --keys-dir /tmp/keys") {
		t.Fatalf("argv = %q", got)
	}

	if err := runBPMShirudoBuildUpatch(context.Background(), bpmShirudoBuildUpatchOptions{
		WorkDir:         dir,
		Source:          "agent.jar",
		Output:          logPath,
		Type:            "java",
		TelemetryUpatch: "javaagent_metrics",
		KeysDir:         "/tmp/keys",
	}, io.Discard, io.Discard); err != nil {
		t.Fatalf("runBPMShirudoBuildUpatch(java) error = %v", err)
	}
	body, err = os.ReadFile(filepath.Join(dir, "build.argv"))
	if err != nil {
		t.Fatalf("read Java argv: %v", err)
	}
	if !strings.Contains(string(body), "--type java --telemetry-upatch javaagent_metrics") {
		t.Fatalf("Java argv = %q", body)
	}
}

func TestBuildBPMUpatchesRejectsDuplicateOutputsBeforeShirudo(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"one.bpf.c", "two.bpf.c"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	oldBuild := bpmShirudoBuildUpatch
	called := false
	bpmShirudoBuildUpatch = func(ctx context.Context, opts bpmShirudoBuildUpatchOptions, stdout io.Writer, stderr io.Writer) error {
		called = true
		return nil
	}
	t.Cleanup(func() {
		bpmShirudoBuildUpatch = oldBuild
	})

	_, err := buildBPMUpatches(context.Background(), bpmBuildSpec{
		ScopeDir: dir,
		Upatches: []bpmBuildUpatchEntry{
			{
				Source:       "one.bpf.c",
				LoadTarget:   "one/dup.upatch",
				UnloadTarget: "one/dup.unload.upatch",
			},
			{
				Source:       "two.bpf.c",
				LoadTarget:   "two/dup.upatch",
				UnloadTarget: "two/dup-2.unload.upatch",
			},
		},
	}, "", io.Discard, io.Discard)
	if err == nil {
		t.Fatalf("buildBPMUpatches() error = nil, want error")
	}
	if called {
		t.Fatalf("shirudo build was called before duplicate output validation failed")
	}
}

func TestRunBPMBuildGeneratesUpatchesAndEnvironmentFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Beefile"), testBPMBuildFileWithUpatch(), 0o600); err != nil {
		t.Fatalf("write Beefile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hello-userns-counter.bpf.c"), []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	wantReadme := "# hello-bee-world\n\nBuilt from README.\n"
	if err := os.WriteFile(filepath.Join(dir, defaultBPMReadmeFile), []byte(wantReadme), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	keysDir := filepath.Join(dir, "keys")
	wantSPKIFingerprint := writeTestBPMShirudoCert(t, keysDir)
	wantCertificate, err := os.ReadFile(filepath.Join(keysDir, defaultBPMBuildPublicCertificateFile))
	if err != nil {
		t.Fatalf("read cert.der: %v", err)
	}

	oldBuild := bpmShirudoBuildUpatch
	bpmShirudoBuildUpatch = func(ctx context.Context, opts bpmShirudoBuildUpatchOptions, stdout io.Writer, stderr io.Writer) error {
		body := testShirudoUpatchBytes(t, "hello-userns-counter", 0, false)
		if opts.Unload {
			body = testShirudoUpatchBytes(t, "hello-userns-counter", shirudoDirectiveUnload, false)
		}
		return os.WriteFile(opts.Output, body, 0o600)
	}
	oldLookPath := bpmBuildLookPath
	bpmBuildLookPath = func(file string) (string, error) {
		return "/usr/bin/shirudo", nil
	}
	oldVersion := bpmShirudoVersion
	bpmShirudoVersion = func(ctx context.Context) (string, error) {
		return "shirudo 1.2.3\n", nil
	}
	oldNow := bpmBuildNow
	bpmBuildNow = func() time.Time {
		return time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	}
	t.Cleanup(func() {
		bpmShirudoBuildUpatch = oldBuild
		bpmBuildLookPath = oldLookPath
		bpmShirudoVersion = oldVersion
		bpmBuildNow = oldNow
	})

	outputPath, err := runBPMBuild(context.Background(), filepath.Join(dir, "Beefile"), "0.1.0", dir, keysDir, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("runBPMBuild() error = %v", err)
	}

	entries := readBPMPackageEntries(t, outputPath)
	var environmentBody string
	var certificateBody string
	var readmeBody string
	for _, entry := range entries {
		if entry.Name == "hello-bee-world-0.1.0/"+defaultBPMBuildEnvironmentFile {
			environmentBody = entry.Body
		}
		if entry.Name == "hello-bee-world-0.1.0/"+defaultBPMBuildPublicCertificateFile {
			certificateBody = entry.Body
		}
		if entry.Name == "hello-bee-world-0.1.0/"+defaultBPMReadmeFile {
			readmeBody = entry.Body
		}
	}
	if environmentBody == "" {
		t.Fatalf("%s not found in package entries %#v", defaultBPMBuildEnvironmentFile, entries)
	}
	if readmeBody != wantReadme {
		t.Fatalf("%s body = %q, want %q", defaultBPMReadmeFile, readmeBody, wantReadme)
	}
	if certificateBody != string(wantCertificate) {
		t.Fatalf("%s body mismatch", defaultBPMBuildPublicCertificateFile)
	}
	for _, field := range []string{`"keys_dir"`, `"public_key_path"`, `"hostname"`, `"working_directory"`, `"public_key_sha256_fingerprint"`, `"public_key_fingerprint_error"`} {
		if strings.Contains(environmentBody, field) {
			t.Fatalf("environment leaked %s field: %s", field, environmentBody)
		}
	}

	var environment bpmBuildEnvironment
	if err := json.Unmarshal([]byte(environmentBody), &environment); err != nil {
		t.Fatalf("unmarshal environment: %v", err)
	}
	if environment.Package.Name != "hello-bee-world" || environment.Package.Version != "0.1.0" {
		t.Fatalf("Package = %#v", environment.Package)
	}
	if environment.CreatedAt != "2026-06-02T12:00:00Z" {
		t.Fatalf("environment = %#v", environment)
	}
	if environment.Shirudo.Path != "/usr/bin/shirudo" || environment.Shirudo.Version != "shirudo 1.2.3" {
		t.Fatalf("Shirudo = %#v", environment.Shirudo)
	}
	if environment.Shirudo.SPKISHA256Fingerprint != wantSPKIFingerprint ||
		environment.Shirudo.SPKIFingerprintError != "" {
		t.Fatalf("Shirudo = %#v", environment.Shirudo)
	}
	if len(environment.Upatches) != 1 ||
		environment.Upatches[0].Source != "hello-userns-counter.bpf.c" ||
		environment.Upatches[0].LoadOutput != "hello-userns-counter.upatch" ||
		environment.Upatches[0].UnloadOutput != "hello-userns-counter.unload.upatch" ||
		environment.Upatches[0].UpatchName != "hello-userns-counter" ||
		environment.Upatches[0].PayloadSHA256 != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" {
		t.Fatalf("Upatches = %#v", environment.Upatches)
	}
}

func TestBPMBuildSPKIFingerprintReadsCertDER(t *testing.T) {
	keysDir := filepath.Join(t.TempDir(), "keys")
	want := writeTestBPMShirudoCert(t, keysDir)

	got, publicKeyPath, err := bpmBuildSPKIFingerprint(keysDir)
	if err != nil {
		t.Fatalf("bpmBuildSPKIFingerprint() error = %v", err)
	}
	if got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}
	if publicKeyPath != filepath.Join(keysDir, "cert.der") {
		t.Fatalf("publicKeyPath = %q", publicKeyPath)
	}
}

func TestRunBPMBuildRequiresPublicCertificateBeforeShirudo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Beefile"), testBPMBuildFileWithUpatch(), 0o600); err != nil {
		t.Fatalf("write Beefile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hello-userns-counter.bpf.c"), []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	oldBuild := bpmShirudoBuildUpatch
	called := false
	bpmShirudoBuildUpatch = func(ctx context.Context, opts bpmShirudoBuildUpatchOptions, stdout io.Writer, stderr io.Writer) error {
		called = true
		return nil
	}
	t.Cleanup(func() {
		bpmShirudoBuildUpatch = oldBuild
	})

	_, err := runBPMBuild(context.Background(), filepath.Join(dir, "Beefile"), "0.1.0", dir, t.TempDir(), io.Discard, io.Discard)
	if err == nil {
		t.Fatalf("runBPMBuild() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "read Shirudo public certificate") {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatalf("shirudo build was called before public certificate validation failed")
	}
}

func TestRunBPMBuildValidatesFilesBeforeShirudo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Beefile"), []byte(`[package]
name = "hello-bee-world"

[[files]]
source = "missing.txt"
target = "share/missing.txt"

[[upatches]]
source = "hello-userns-counter.bpf.c"
load_target = "upatches/hello-userns-counter.upatch"
unload_target = "upatches/hello-userns-counter.unload.upatch"
`), 0o600); err != nil {
		t.Fatalf("write Beefile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hello-userns-counter.bpf.c"), []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	oldBuild := bpmShirudoBuildUpatch
	called := false
	bpmShirudoBuildUpatch = func(ctx context.Context, opts bpmShirudoBuildUpatchOptions, stdout io.Writer, stderr io.Writer) error {
		called = true
		return nil
	}
	t.Cleanup(func() {
		bpmShirudoBuildUpatch = oldBuild
	})

	_, err := runBPMBuild(context.Background(), filepath.Join(dir, "Beefile"), "0.1.0", dir, "", io.Discard, io.Discard)
	if err == nil {
		t.Fatalf("runBPMBuild() error = nil, want error")
	}
	if called {
		t.Fatalf("shirudo build was called before file validation failed")
	}
}

func writeTestBPMShirudoCert(t *testing.T, keysDir string) string {
	t.Helper()

	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(4102444800, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "cert.der"), certDER, 0o600); err != nil {
		t.Fatalf("write cert.der: %v", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	fingerprint := sha256.Sum256(publicKeyDER)

	return hex.EncodeToString(fingerprint[:])
}
