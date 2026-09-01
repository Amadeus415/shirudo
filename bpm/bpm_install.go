package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

const defaultBPMInstallDir = ".bpm"
const defaultBPMConfigFile = "config.toml"

var bpmUserHomeDir = os.UserHomeDir
var bpmShirudoUpatchLoad = runBPMShirudoUpatchLoad
var bpmShirudoUpatchUnload = runBPMShirudoUpatchUnload

func installBPMPackage(ctx context.Context, rawReference string, installRoot string, configPaths []string, httpClient *http.Client, stdout io.Writer, stderr io.Writer) (string, error) {
	archive, err := loadBPMPackageArchiveFromSource(ctx, rawReference, httpClient)
	if err != nil {
		return "", err
	}

	return installBPMPackageArchive(ctx, archive.Body, installRoot, configPaths, stdout, stderr)
}

func installBPMPackageArchive(ctx context.Context, packageBody []byte, installRoot string, configPaths []string, stdout io.Writer, stderr io.Writer) (string, error) {
	manifest, err := readBPMPackageManifest(packageBody)
	if err != nil {
		return "", fmt.Errorf("read package manifest: %w", err)
	}

	root, err := prepareBPMInstallRoot(installRoot)
	if err != nil {
		return "", err
	}

	if err := ensureBPMNoInstalledPackageConflict(root, manifest); err != nil {
		return "", err
	}

	packageDir := manifest.Name + "-" + manifest.Version
	installDir := filepath.Join(root, packageDir)
	if err := extractBPMPackageArchive(packageBody, root, packageDir); err != nil {
		return "", err
	}
	configPaths, err = bpmInstallConfigPaths(installDir, configPaths)
	if err != nil {
		return "", err
	}

	for _, upatch := range manifest.Upatches {
		upatchPath, err := bpmInstalledUpatchPath(installDir, upatch.LoadPath, "upatches.load_target")
		if err != nil {
			return "", err
		}
		info, err := os.Stat(upatchPath)
		if err != nil {
			return "", fmt.Errorf("stat upatch %s: %w", upatch.LoadPath, err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("upatch %s is a directory", upatch.LoadPath)
		}
		if err := bpmShirudoUpatchLoad(ctx, upatchPath, configPaths, stdout, stderr); err != nil {
			return "", fmt.Errorf("load upatch %s: %w", upatch.LoadPath, err)
		}
	}

	return installDir, nil
}

func listBPMInstalledPackages(installRoot string) ([]string, error) {
	root, err := prepareBPMInstallRoot(installRoot)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read install directory %s: %w", root, err)
	}

	packages := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			packages = append(packages, entry.Name())
		}
	}

	return packages, nil
}

func ensureBPMNoInstalledPackageConflict(root string, manifest bpmPackageManifest) error {
	installed, err := findBPMInstalledPackagesByName(root, manifest.Name)
	if err != nil {
		return err
	}
	for _, pkg := range installed {
		return fmt.Errorf("%s is already installed; uninstall it first with: 'bpm uninstall %s'", pkg, pkg)
	}

	return nil
}

func findBPMInstalledPackagesByName(root string, packageName string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read install directory %s: %w", root, err)
	}

	var installed []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		installDir := filepath.Join(root, name)
		if !pathWithinDir(root, installDir) {
			return nil, fmt.Errorf("install path %s escapes install directory %s", installDir, root)
		}
		manifest, err := readBPMInstalledPackageManifest(installDir)
		if err != nil {
			continue
		}
		if manifest.Name == packageName {
			installed = append(installed, name)
		}
	}

	return installed, nil
}

func uninstallBPMPackage(ctx context.Context, packageName string, installRoot string, stdout io.Writer, stderr io.Writer) (string, error) {
	root, err := prepareBPMInstallRoot(installRoot)
	if err != nil {
		return "", err
	}

	installDir, manifest, err := installedBPMPackageForName(root, packageName)
	if err != nil {
		return "", err
	}

	for i := len(manifest.Upatches) - 1; i >= 0; i-- {
		upatch := manifest.Upatches[i]
		upatchPath, err := bpmInstalledUpatchPath(installDir, upatch.UnloadPath, "upatches.unload_target")
		if err != nil {
			return "", err
		}
		info, err := os.Stat(upatchPath)
		if err != nil {
			return "", fmt.Errorf("stat unload upatch %s: %w", upatch.UnloadPath, err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("unload upatch %s is a directory", upatch.UnloadPath)
		}
		if err := bpmShirudoUpatchUnload(ctx, upatchPath, stdout, stderr); err != nil {
			return "", fmt.Errorf("unload upatch %s: %w", upatch.UnloadPath, err)
		}
	}

	if err := removeBPMInstalledPackage(root, installDir); err != nil {
		return "", err
	}

	return installDir, nil
}

func prepareBPMInstallRoot(installRoot string) (string, error) {
	installRoot = strings.TrimSpace(installRoot)
	if installRoot == "" {
		root, err := defaultBPMInstallRoot()
		if err != nil {
			return "", err
		}
		installRoot = root
	}

	root, err := filepath.Abs(installRoot)
	if err != nil {
		return "", fmt.Errorf("resolve install directory %s: %w", installRoot, err)
	}
	if err := safeBPMMkdirAll(root, root, 0o755); err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve install directory %s: %w", installRoot, err)
	}

	return root, nil
}

func defaultBPMInstallRoot() (string, error) {
	home, err := bpmUserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	home = strings.TrimSpace(home)
	if home == "" {
		return "", fmt.Errorf("home directory is empty")
	}

	return filepath.Join(home, defaultBPMInstallDir), nil
}

func extractBPMPackageArchive(packageBody []byte, installRoot string, packageDir string) error {
	gzipReader, err := gzip.NewReader(bytes.NewReader(packageBody))
	if err != nil {
		return fmt.Errorf("open package gzip: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read package tar: %w", err)
		}

		rel, err := normalizeBPMPackageTarEntry(header.Name, packageDir)
		if err != nil {
			return err
		}
		dest := filepath.Join(installRoot, filepath.FromSlash(rel))
		if !pathWithinDir(installRoot, dest) {
			return fmt.Errorf("package entry %q escapes install directory", header.Name)
		}

		mode := header.FileInfo().Mode().Perm()
		switch header.Typeflag {
		case tar.TypeDir:
			if mode == 0 {
				mode = 0o755
			}
			if err := safeBPMMkdirAll(installRoot, dest, mode); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if mode == 0 {
				mode = 0o644
			}
			if err := writeBPMInstallFile(installRoot, dest, mode, tarReader); err != nil {
				return err
			}
		default:
			return fmt.Errorf("package entry %q has unsupported type %d", header.Name, header.Typeflag)
		}
	}

	return nil
}

func normalizeBPMPackageTarEntry(name string, packageDir string) (string, error) {
	name = strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if name == "" {
		return "", fmt.Errorf("package contains an empty path")
	}
	if path.IsAbs(name) {
		return "", fmt.Errorf("package entry %q must be relative", name)
	}
	for _, component := range strings.Split(name, "/") {
		if component == ".." {
			return "", fmt.Errorf("package entry %q escapes the package directory", name)
		}
	}

	cleanName := path.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return "", fmt.Errorf("package entry %q escapes the package directory", name)
	}
	if cleanName != packageDir && !strings.HasPrefix(cleanName, packageDir+"/") {
		return "", fmt.Errorf("package entry %q is outside expected directory %q", name, packageDir)
	}

	return cleanName, nil
}

func writeBPMInstallFile(root string, dest string, mode os.FileMode, reader io.Reader) error {
	if err := safeBPMMkdirAll(root, filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(dest); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("install path %s is a symlink", dest)
		}
		if info.IsDir() {
			return fmt.Errorf("install path %s is a directory", dest)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat install path %s: %w", dest, err)
	}

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("write install file %s: %w", dest, err)
	}
	if _, err := io.Copy(out, reader); err != nil {
		out.Close()
		return fmt.Errorf("write install file %s: %w", dest, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close install file %s: %w", dest, err)
	}

	return nil
}

func safeBPMMkdirAll(root string, dir string, mode os.FileMode) error {
	if !pathWithinDir(root, dir) {
		return fmt.Errorf("install path %s escapes install directory %s", dir, root)
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return fmt.Errorf("resolve install path %s: %w", dir, err)
	}
	if rel == "." {
		if err := os.MkdirAll(root, mode); err != nil {
			return fmt.Errorf("create install directory %s: %w", root, err)
		}
		return nil
	}

	current := root
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("install path %s is a symlink", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("install path %s is not a directory", current)
			}
		case os.IsNotExist(err):
			if err := os.Mkdir(current, mode); err != nil {
				return fmt.Errorf("create install directory %s: %w", current, err)
			}
		default:
			return fmt.Errorf("stat install directory %s: %w", current, err)
		}
	}

	return nil
}

func installedBPMPackageForName(root string, packageName string) (string, bpmPackageManifest, error) {
	packageName = strings.TrimSpace(packageName)
	if packageName == "" {
		return "", bpmPackageManifest{}, fmt.Errorf("package name is empty")
	}
	if filepath.IsAbs(packageName) || packageName != filepath.Base(packageName) {
		return "", bpmPackageManifest{}, fmt.Errorf("package name %q must be an installed package directory name", packageName)
	}
	if !bpmPackageVersionPattern.MatchString(packageName) {
		return "", bpmPackageManifest{}, fmt.Errorf("package name %q cannot be used as an install directory", packageName)
	}

	installDir := filepath.Join(root, packageName)
	if !pathWithinDir(root, installDir) {
		return "", bpmPackageManifest{}, fmt.Errorf("install path %s escapes install directory %s", installDir, root)
	}

	manifest, err := readBPMInstalledPackageManifest(installDir)
	if err != nil {
		return "", bpmPackageManifest{}, err
	}

	return installDir, manifest, nil
}

func readBPMInstalledPackageManifest(installDir string) (bpmPackageManifest, error) {
	body, err := os.ReadFile(filepath.Join(installDir, defaultBPMBuildFile))
	if err != nil {
		return bpmPackageManifest{}, fmt.Errorf("read installed Beefile: %w", err)
	}

	manifest, err := parseBPMPackageManifest(body, filepath.Base(installDir))
	if err != nil {
		return bpmPackageManifest{}, fmt.Errorf("parse installed Beefile: %w", err)
	}

	return manifest, nil
}

func removeBPMInstalledPackage(root string, installDir string) error {
	if !pathWithinDir(root, installDir) {
		return fmt.Errorf("install path %s escapes install directory %s", installDir, root)
	}
	rel, err := filepath.Rel(root, installDir)
	if err != nil {
		return fmt.Errorf("resolve install path %s: %w", installDir, err)
	}
	if rel == "." {
		return fmt.Errorf("refusing to remove install root %s", root)
	}
	info, err := os.Lstat(installDir)
	if err != nil {
		return fmt.Errorf("stat install directory %s: %w", installDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("install directory %s is a symlink", installDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("install path %s is not a directory", installDir)
	}
	if err := os.RemoveAll(installDir); err != nil {
		return fmt.Errorf("remove install directory %s: %w", installDir, err)
	}

	return nil
}

func bpmInstalledUpatchPath(installDir string, packagePath string, field string) (string, error) {
	rel, err := normalizeBPMArchivePath(packagePath, field)
	if err != nil {
		return "", err
	}
	upatchPath := filepath.Join(installDir, filepath.FromSlash(rel))
	if !pathWithinDir(installDir, upatchPath) {
		return "", fmt.Errorf("upatch path %q escapes install directory", packagePath)
	}

	return upatchPath, nil
}

func bpmInstalledConfigPath(installDir string) (string, error) {
	configPath := filepath.Join(installDir, defaultBPMConfigFile)
	if !pathWithinDir(installDir, configPath) {
		return "", fmt.Errorf("config path escapes install directory")
	}

	info, err := os.Lstat(configPath)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%s is a symlink", defaultBPMConfigFile)
		}
		if info.IsDir() {
			return "", fmt.Errorf("%s is a directory", defaultBPMConfigFile)
		}
		return configPath, nil
	case os.IsNotExist(err):
		return "", nil
	default:
		return "", fmt.Errorf("stat %s: %w", defaultBPMConfigFile, err)
	}
}

func bpmInstallConfigPaths(installDir string, additionalConfigPaths []string) ([]string, error) {
	packageConfigPath, err := bpmInstalledConfigPath(installDir)
	if err != nil {
		return nil, err
	}

	configPaths := make([]string, 0, len(additionalConfigPaths)+1)
	if packageConfigPath != "" {
		configPaths = append(configPaths, packageConfigPath)
	}
	configPaths = append(configPaths, additionalConfigPaths...)

	return configPaths, nil
}

func runBPMShirudoUpatchLoad(ctx context.Context, upatchPath string, configPaths []string, stdout io.Writer, stderr io.Writer) error {
	args := []string{"upatch", "load"}
	for _, configPath := range configPaths {
		if strings.TrimSpace(configPath) == "" {
			continue
		}
		args = append(args, "-f", configPath)
	}
	args = append(args, upatchPath)

	command := exec.CommandContext(ctx, "shirudo", args...)
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func runBPMShirudoUpatchUnload(ctx context.Context, upatchPath string, stdout io.Writer, stderr io.Writer) error {
	command := exec.CommandContext(ctx, "shirudo", "upatch", "unload", upatchPath)
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}
