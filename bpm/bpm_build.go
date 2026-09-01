package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var bpmShirudoBuildUpatch = runBPMShirudoBuildUpatch
var bpmShirudoVersion = runBPMShirudoVersion
var bpmBuildLookPath = exec.LookPath
var bpmBuildNow = time.Now

type bpmShirudoBuildUpatchOptions struct {
	WorkDir         string
	Source          string
	Output          string
	Type            string
	TelemetryUpatch string
	Unload          bool
	UnloadName      string
	PayloadSHA256   string
	KeysDir         string
}

type bpmBuiltUpatch struct {
	Source           string
	Type             string
	TelemetryUpatch  string
	LoadTarget       string
	LoadOutput       string
	LoadOutputPath   string
	UnloadTarget     string
	UnloadOutput     string
	UnloadOutputPath string
	UpatchName       string
	PayloadSHA256    string
}

type bpmUpatchBuildPlan struct {
	WorkDir          string
	Built            bpmBuiltUpatch
	Source           string
	LoadOutputPath   string
	UnloadOutputPath string
}

type bpmBuildEnvironment struct {
	FormatVersion int                         `json:"format_version"`
	Builder       string                      `json:"builder"`
	CreatedAt     string                      `json:"created_at"`
	Package       bpmBuildEnvironmentPackage  `json:"package"`
	OS            string                      `json:"os"`
	Arch          string                      `json:"arch"`
	GoVersion     string                      `json:"go_version"`
	BPMVersion    string                      `json:"bpm_version"`
	Shirudo       bpmBuildEnvironmentShirudo  `json:"shirudo"`
	Upatches      []bpmBuildEnvironmentUpatch `json:"upatches"`
}

type bpmBuildEnvironmentPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type bpmBuildEnvironmentShirudo struct {
	Path                  string `json:"path,omitempty"`
	Version               string `json:"version,omitempty"`
	SPKISHA256Fingerprint string `json:"spki_sha256_fingerprint,omitempty"`
	SPKIFingerprintError  string `json:"spki_fingerprint_error,omitempty"`
	LookupError           string `json:"lookup_error,omitempty"`
	VersionError          string `json:"version_error,omitempty"`
}

type bpmBuildEnvironmentUpatch struct {
	Source          string `json:"source"`
	Type            string `json:"type"`
	TelemetryUpatch string `json:"telemetry_upatch,omitempty"`
	LoadTarget      string `json:"load_target"`
	LoadOutput      string `json:"load_output"`
	UnloadTarget    string `json:"unload_target"`
	UnloadOutput    string `json:"unload_output"`
	UpatchName      string `json:"upatch_name,omitempty"`
	PayloadSHA256   string `json:"payload_sha256,omitempty"`
}

func runBPMBuild(ctx context.Context, buildFilePath string, version string, outputDir string, keysDir string, stdout io.Writer, stderr io.Writer) (string, error) {
	version, err := normalizeBPMBuildVersion(version)
	if err != nil {
		return "", err
	}
	keysDir, err = resolveBPMBuildKeysDir(keysDir)
	if err != nil {
		return "", err
	}

	spec, err := loadBPMBuildSpec(buildFilePath)
	if err != nil {
		return "", err
	}
	if err := validateBPMBuildPackageTargets(spec.Files, spec.Upatches); err != nil {
		return "", err
	}
	if err := validateBPMBuildFileSources(spec.ScopeDir, spec.Files); err != nil {
		return "", err
	}

	publicCertificateFile, spkiFingerprint, err := bpmBuildPublicCertificateFile(keysDir)
	if err != nil {
		return "", err
	}
	builtUpatches, err := buildBPMUpatches(ctx, spec, keysDir, stdout, stderr)
	if err != nil {
		return "", err
	}
	files, err := resolveBPMBuildPackageFiles(spec.ScopeDir, spec.Files, spec.Upatches)
	if err != nil {
		return "", err
	}
	readmeFile, ok, err := bpmBuildReadmeFile(spec.ScopeDir)
	if err != nil {
		return "", err
	}
	if ok {
		files = append(files, readmeFile)
	}
	files = append(files, publicCertificateFile)
	environmentFile, err := bpmBuildEnvironmentFile(ctx, spec, version, spkiFingerprint, builtUpatches)
	if err != nil {
		return "", err
	}
	files = append(files, environmentFile)

	return buildBPMPackage(outputDir, spec.BuildFile, spec.Metadata, version, files...)
}

func bpmBuildReadmeFile(scopeDir string) (bpmPackageFile, bool, error) {
	scopePath, err := resolveBPMBuildScopePath(scopeDir)
	if err != nil {
		return bpmPackageFile{}, false, err
	}
	readmePath := filepath.Join(scopePath, defaultBPMReadmeFile)
	if _, err := os.Stat(readmePath); err != nil {
		if os.IsNotExist(err) {
			return bpmPackageFile{}, false, nil
		}
		return bpmPackageFile{}, false, fmt.Errorf("stat %s: %w", readmePath, err)
	}

	sourcePath, info, err := resolveBPMBuildFileSource(scopePath, defaultBPMReadmeFile, "README")
	if err != nil {
		return bpmPackageFile{}, false, err
	}
	body, err := os.ReadFile(sourcePath)
	if err != nil {
		return bpmPackageFile{}, false, fmt.Errorf("read %s: %w", readmePath, err)
	}

	return bpmPackageFile{
		Target: defaultBPMReadmeFile,
		Body:   body,
		Mode:   int64(info.Mode().Perm()),
	}, true, nil
}

func validateBPMBuildFileSources(scopeDir string, files []bpmBuildFileEntry) error {
	scopePath, err := resolveBPMBuildScopePath(scopeDir)
	if err != nil {
		return err
	}
	for _, file := range files {
		if _, _, err := resolveBPMBuildFileSource(scopePath, file.Source, "files"); err != nil {
			return err
		}
	}

	return nil
}

func buildBPMUpatches(ctx context.Context, spec bpmBuildSpec, keysDir string, stdout io.Writer, stderr io.Writer) ([]bpmBuiltUpatch, error) {
	plans, err := planBPMUpatchBuilds(spec)
	if err != nil {
		return nil, err
	}

	built := make([]bpmBuiltUpatch, 0, len(plans))
	for _, plan := range plans {
		if err := buildBPMUpatch(ctx, bpmShirudoBuildUpatchOptions{
			WorkDir:         plan.WorkDir,
			Source:          plan.Source,
			Output:          plan.LoadOutputPath,
			Type:            plan.Built.Type,
			TelemetryUpatch: plan.Built.TelemetryUpatch,
			KeysDir:         keysDir,
		}, stdout, stderr); err != nil {
			return nil, fmt.Errorf("build upatch %s: %w", plan.Built.LoadTarget, err)
		}
		load, err := readBPMShirudoLoadUpatch(plan.LoadOutputPath)
		if err != nil {
			return nil, fmt.Errorf("read generated upatch %s: %w", plan.Built.LoadTarget, err)
		}
		if err := buildBPMUpatch(ctx, bpmShirudoBuildUpatchOptions{
			WorkDir:       plan.WorkDir,
			Output:        plan.UnloadOutputPath,
			Type:          load.PayloadType,
			Unload:        true,
			UnloadName:    load.Name,
			PayloadSHA256: load.PayloadSHA256,
			KeysDir:       keysDir,
		}, stdout, stderr); err != nil {
			return nil, fmt.Errorf("build unload upatch %s: %w", plan.Built.UnloadTarget, err)
		}
		plan.Built.UpatchName = load.Name
		plan.Built.Type = load.PayloadType
		plan.Built.PayloadSHA256 = load.PayloadSHA256
		built = append(built, plan.Built)
	}

	return built, nil
}

func planBPMUpatchBuilds(spec bpmBuildSpec) ([]bpmUpatchBuildPlan, error) {
	scopePath, err := resolveBPMBuildScopePath(spec.ScopeDir)
	if err != nil {
		return nil, err
	}

	seenOutputs := map[string]struct{}{}
	plans := make([]bpmUpatchBuildPlan, 0, len(spec.Upatches))
	for _, upatch := range spec.Upatches {
		sourceRel, err := resolveBPMBuildUpatchSource(scopePath, upatch.Source)
		if err != nil {
			return nil, err
		}

		loadOutput, loadOutputPath, err := bpmBuildUpatchOutputPath(scopePath, upatch.LoadTarget, "upatches.load_target")
		if err != nil {
			return nil, err
		}
		unloadOutput, unloadOutputPath, err := bpmBuildUpatchOutputPath(scopePath, upatch.UnloadTarget, "upatches.unload_target")
		if err != nil {
			return nil, err
		}
		for _, output := range []string{loadOutput, unloadOutput} {
			if _, ok := seenOutputs[output]; ok {
				return nil, fmt.Errorf("upatch output %q is duplicated", output)
			}
			seenOutputs[output] = struct{}{}
		}

		plans = append(plans, bpmUpatchBuildPlan{
			WorkDir: scopePath,
			Built: bpmBuiltUpatch{
				Source:           upatch.Source,
				Type:             bpmBuildUpatchType(upatch),
				TelemetryUpatch:  upatch.TelemetryUpatch,
				LoadTarget:       upatch.LoadTarget,
				LoadOutput:       loadOutput,
				LoadOutputPath:   loadOutputPath,
				UnloadTarget:     upatch.UnloadTarget,
				UnloadOutput:     unloadOutput,
				UnloadOutputPath: unloadOutputPath,
			},
			Source:           sourceRel,
			LoadOutputPath:   loadOutputPath,
			UnloadOutputPath: unloadOutputPath,
		})
	}

	return plans, nil
}

func buildBPMUpatch(ctx context.Context, opts bpmShirudoBuildUpatchOptions, stdout io.Writer, stderr io.Writer) error {
	if err := prepareBPMUpatchOutput(opts.Output); err != nil {
		return err
	}
	if err := bpmShirudoBuildUpatch(ctx, opts, stdout, stderr); err != nil {
		return err
	}
	info, err := os.Stat(opts.Output)
	if err != nil {
		return fmt.Errorf("stat generated upatch %s: %w", opts.Output, err)
	}
	if info.IsDir() {
		return fmt.Errorf("generated upatch %s is a directory", opts.Output)
	}

	return nil
}

func readBPMShirudoLoadUpatch(path string) (shirudoUpatchHeader, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return shirudoUpatchHeader{}, err
	}
	upatch, err := parseShirudoUpatch(body)
	if err != nil {
		return shirudoUpatchHeader{}, err
	}
	if upatch.Directive != "load" {
		return shirudoUpatchHeader{}, fmt.Errorf("cannot build unload companion for upatch directive %q", upatch.Directive)
	}
	if strings.TrimSpace(upatch.Name) == "" {
		return shirudoUpatchHeader{}, fmt.Errorf("cannot build unload companion: upatch name is empty")
	}
	if strings.TrimSpace(upatch.PayloadSHA256) == "" {
		return shirudoUpatchHeader{}, fmt.Errorf("cannot build unload companion: payload sha256 is empty")
	}

	return upatch, nil
}

func resolveBPMBuildUpatchSource(scopePath string, source string) (string, error) {
	if _, _, err := resolveBPMBuildFileSource(scopePath, source, "upatches"); err != nil {
		return "", err
	}
	source = strings.TrimSpace(source)
	source = strings.ReplaceAll(source, "\\", string(filepath.Separator))
	return filepath.Clean(source), nil
}

func bpmBuildUpatchOutputPath(scopePath string, target string, field string) (string, string, error) {
	cleanTarget, err := normalizeBPMArchivePath(target, field)
	if err != nil {
		return "", "", err
	}
	output := path.Base(cleanTarget)
	if output == "." || output == "/" || output == "" {
		return "", "", fmt.Errorf("%s %q does not name an upatch output file", field, target)
	}
	outputPath := filepath.Join(scopePath, filepath.FromSlash(output))
	if !pathWithinDir(scopePath, outputPath) {
		return "", "", fmt.Errorf("%s %q escapes the Beefile directory", field, target)
	}

	return output, outputPath, nil
}

func prepareBPMUpatchOutput(outputPath string) error {
	info, err := os.Lstat(outputPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat upatch output %s: %w", outputPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("upatch output %s is a directory", outputPath)
	}
	if err := os.Remove(outputPath); err != nil {
		return fmt.Errorf("remove existing upatch output %s: %w", outputPath, err)
	}

	return nil
}

func runBPMShirudoBuildUpatch(ctx context.Context, opts bpmShirudoBuildUpatchOptions, stdout io.Writer, stderr io.Writer) error {
	args := []string{"build"}
	payloadType := strings.ToLower(strings.TrimSpace(opts.Type))
	if payloadType == "" {
		payloadType = "bpf"
	}
	if payloadType != "bpf" && payloadType != "java" {
		return fmt.Errorf("upatch type must be bpf or java")
	}
	if opts.Unload {
		name := strings.TrimSpace(opts.UnloadName)
		if name == "" {
			return fmt.Errorf("unload upatch name is empty")
		}
		payloadSHA256 := strings.TrimSpace(opts.PayloadSHA256)
		if payloadSHA256 == "" {
			return fmt.Errorf("unload upatch payload sha256 is empty")
		}
		args = append(args, "--unload", name, "--payload-sha256", payloadSHA256)
	} else {
		args = append(args, opts.Source)
	}
	args = append(args, "-o", opts.Output)
	if keysDir := strings.TrimSpace(opts.KeysDir); keysDir != "" {
		args = append(args, "--keys-dir", keysDir)
	}
	args = append(args, "--type", payloadType)
	if !opts.Unload && strings.TrimSpace(opts.TelemetryUpatch) != "" {
		args = append(args, "--telemetry-upatch", strings.TrimSpace(opts.TelemetryUpatch))
	}

	command := exec.CommandContext(ctx, "shirudo", args...)
	command.Dir = opts.WorkDir
	command.Stdout = stdout
	command.Stderr = stderr

	return command.Run()
}

func bpmBuildEnvironmentFile(ctx context.Context, spec bpmBuildSpec, buildVersion string, spkiFingerprint string, builtUpatches []bpmBuiltUpatch) (bpmPackageFile, error) {
	env := bpmBuildEnvironment{
		FormatVersion: 1,
		Builder:       "bpm build",
		CreatedAt:     bpmBuildNow().UTC().Format(time.RFC3339),
		Package:       bpmBuildEnvironmentPackage{Name: spec.Metadata.Name, Version: buildVersion},
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		GoVersion:     runtime.Version(),
		BPMVersion:    version,
		Shirudo:       bpmBuildShirudoEnvironment(ctx, spkiFingerprint),
		Upatches:      bpmBuildUpatchEnvironment(builtUpatches),
	}

	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return bpmPackageFile{}, fmt.Errorf("marshal build environment: %w", err)
	}
	body = append(body, '\n')

	return bpmPackageFile{
		Target: defaultBPMBuildEnvironmentFile,
		Body:   body,
		Mode:   0o644,
	}, nil
}

func bpmBuildShirudoEnvironment(ctx context.Context, spkiFingerprint string) bpmBuildEnvironmentShirudo {
	env := bpmBuildEnvironmentShirudo{
		SPKISHA256Fingerprint: strings.TrimSpace(spkiFingerprint),
	}

	path, err := bpmBuildLookPath("shirudo")
	if err != nil {
		env.LookupError = err.Error()
		return env
	}
	env.Path = path

	shirudoVersion, err := bpmShirudoVersion(ctx)
	if err != nil {
		env.VersionError = err.Error()
	}
	env.Version = strings.TrimSpace(shirudoVersion)

	return env
}

func bpmBuildPublicCertificateFile(keysDir string) (bpmPackageFile, string, error) {
	fingerprint, _, body, err := bpmBuildPublicCertificate(keysDir)
	if err != nil {
		return bpmPackageFile{}, "", err
	}

	return bpmPackageFile{
		Target: defaultBPMBuildPublicCertificateFile,
		Body:   body,
		Mode:   0o644,
	}, fingerprint, nil
}

func bpmBuildPublicCertificate(keysDir string) (string, string, []byte, error) {
	keysDir = strings.TrimSpace(keysDir)
	if keysDir == "" {
		return "", "", nil, fmt.Errorf("keys directory is empty")
	}

	publicKeyPath := filepath.Join(keysDir, defaultBPMBuildPublicCertificateFile)
	body, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", publicKeyPath, nil, fmt.Errorf("read Shirudo public certificate: %w", err)
	}
	fingerprint, err := bpmSPKISHA256Fingerprint(body)
	if err != nil {
		return "", publicKeyPath, nil, err
	}

	return fingerprint, publicKeyPath, body, nil
}

func bpmBuildSPKIFingerprint(keysDir string) (string, string, error) {
	fingerprint, publicKeyPath, _, err := bpmBuildPublicCertificate(keysDir)
	return fingerprint, publicKeyPath, err
}

func bpmSPKISHA256Fingerprint(body []byte) (string, error) {
	cert, err := x509.ParseCertificate(body)
	if err != nil {
		return "", fmt.Errorf("parse Shirudo public certificate: %w", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal Shirudo SPKI: %w", err)
	}
	fingerprint := sha256.Sum256(spkiDER)

	return fmt.Sprintf("%x", fingerprint[:]), nil
}

func bpmBuildUpatchEnvironment(builtUpatches []bpmBuiltUpatch) []bpmBuildEnvironmentUpatch {
	upatches := make([]bpmBuildEnvironmentUpatch, 0, len(builtUpatches))
	for _, upatch := range builtUpatches {
		upatches = append(upatches, bpmBuildEnvironmentUpatch{
			Source:          upatch.Source,
			Type:            upatch.Type,
			TelemetryUpatch: upatch.TelemetryUpatch,
			LoadTarget:      upatch.LoadTarget,
			LoadOutput:      upatch.LoadOutput,
			UnloadTarget:    upatch.UnloadTarget,
			UnloadOutput:    upatch.UnloadOutput,
			UpatchName:      upatch.UpatchName,
			PayloadSHA256:   upatch.PayloadSHA256,
		})
	}
	return upatches
}

func runBPMShirudoVersion(ctx context.Context) (string, error) {
	command := exec.CommandContext(ctx, "shirudo", "version")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return output.String(), err
	}

	return output.String(), nil
}
