package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

type bpmPackageArchive struct {
	Metadata bpmPackageManifest
	Body     []byte
}

type bpmPackageManifest struct {
	Name        string
	Version     string
	Description string
	License     string
	Authors     []string
	Upatches    []bpmPackageUpatch
}

type bpmPackageUpatch struct {
	LoadPath   string
	UnloadPath string
}

func loadBPMPackageArchive(packagePath string) (bpmPackageArchive, error) {
	packagePath = strings.TrimSpace(packagePath)
	if packagePath == "" {
		return bpmPackageArchive{}, fmt.Errorf("package file is empty")
	}

	body, err := os.ReadFile(packagePath)
	if err != nil {
		return bpmPackageArchive{}, fmt.Errorf("read package file %s: %w", packagePath, err)
	}

	manifest, err := readBPMPackageManifest(body)
	if err != nil {
		return bpmPackageArchive{}, fmt.Errorf("read package manifest: %w", err)
	}

	return bpmPackageArchive{
		Metadata: manifest,
		Body:     body,
	}, nil
}

func readBPMPackageManifest(packageBody []byte) (bpmPackageManifest, error) {
	body, packageDir, err := readBPMPackageBeefile(packageBody)
	if err != nil {
		return bpmPackageManifest{}, err
	}

	return parseBPMPackageManifest(body, packageDir)
}

func readBPMPackageBeefile(packageBody []byte) ([]byte, string, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(packageBody))
	if err != nil {
		return nil, "", fmt.Errorf("open gzip: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("read tar: %w", err)
		}
		if header.Typeflag == tar.TypeDir || path.Base(header.Name) != defaultBPMBuildFile {
			continue
		}

		packageDir, err := packageDirFromBeefileEntry(header.Name)
		if err != nil {
			return nil, "", err
		}
		body, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, "", fmt.Errorf("read Beefile: %w", err)
		}
		return body, packageDir, nil
	}

	return nil, "", fmt.Errorf("Beefile not found")
}

func readBPMPackageReadme(packageBody []byte) ([]byte, bool, error) {
	_, packageDir, err := readBPMPackageBeefile(packageBody)
	if err != nil {
		return nil, false, err
	}
	wantName := path.Join(packageDir, defaultBPMReadmeFile)

	gzipReader, err := gzip.NewReader(bytes.NewReader(packageBody))
	if err != nil {
		return nil, false, fmt.Errorf("open gzip: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, fmt.Errorf("read tar: %w", err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}

		name := strings.ReplaceAll(strings.TrimSpace(header.Name), "\\", "/")
		if path.Clean(name) != wantName {
			continue
		}

		body, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, false, fmt.Errorf("read README: %w", err)
		}
		return body, true, nil
	}

	return nil, false, nil
}

func readBPMPackageBuildEnvironment(packageBody []byte) (bpmBuildEnvironment, bool, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(packageBody))
	if err != nil {
		return bpmBuildEnvironment{}, false, fmt.Errorf("open gzip: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return bpmBuildEnvironment{}, false, fmt.Errorf("read tar: %w", err)
		}
		if header.Typeflag == tar.TypeDir || path.Base(header.Name) != defaultBPMBuildEnvironmentFile {
			continue
		}
		if err := validateBPMPackageBuildEnvironmentEntry(header.Name); err != nil {
			return bpmBuildEnvironment{}, false, err
		}

		body, err := io.ReadAll(tarReader)
		if err != nil {
			return bpmBuildEnvironment{}, false, fmt.Errorf("read build environment: %w", err)
		}
		var environment bpmBuildEnvironment
		if err := json.Unmarshal(body, &environment); err != nil {
			return bpmBuildEnvironment{}, false, fmt.Errorf("decode build environment: %w", err)
		}
		return environment, true, nil
	}

	return bpmBuildEnvironment{}, false, nil
}

func readBPMPackagePublicCertificate(packageBody []byte) ([]byte, bool, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(packageBody))
	if err != nil {
		return nil, false, fmt.Errorf("open gzip: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, fmt.Errorf("read tar: %w", err)
		}
		if header.Typeflag == tar.TypeDir || path.Base(header.Name) != defaultBPMBuildPublicCertificateFile {
			continue
		}
		if err := validateBPMPackagePublicCertificateEntry(header.Name); err != nil {
			return nil, false, err
		}

		body, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, false, fmt.Errorf("read public certificate: %w", err)
		}
		return body, true, nil
	}

	return nil, false, nil
}

func packageDirFromBeefileEntry(name string) (string, error) {
	name = strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if name == "" {
		return "", fmt.Errorf("package contains an empty path")
	}
	if path.IsAbs(name) {
		return "", fmt.Errorf("package Beefile entry %q must be relative", name)
	}
	for _, component := range strings.Split(name, "/") {
		if component == ".." {
			return "", fmt.Errorf("package Beefile entry %q escapes the package directory", name)
		}
	}

	cleanName := path.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return "", fmt.Errorf("package Beefile entry %q escapes the package directory", name)
	}
	if path.Base(cleanName) != defaultBPMBuildFile {
		return "", fmt.Errorf("package Beefile entry %q has unexpected name", name)
	}

	packageDir := path.Dir(cleanName)
	if packageDir == "." || packageDir == "/" || strings.Contains(packageDir, "/") {
		return "", fmt.Errorf("package Beefile entry %q must be in the package directory root", name)
	}

	return packageDir, nil
}

func validateBPMPackageBuildEnvironmentEntry(name string) error {
	name = strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if name == "" {
		return fmt.Errorf("package contains an empty path")
	}
	if path.IsAbs(name) {
		return fmt.Errorf("package build environment entry %q must be relative", name)
	}
	for _, component := range strings.Split(name, "/") {
		if component == ".." {
			return fmt.Errorf("package build environment entry %q escapes the package directory", name)
		}
	}

	cleanName := path.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return fmt.Errorf("package build environment entry %q escapes the package directory", name)
	}
	if path.Base(cleanName) != defaultBPMBuildEnvironmentFile {
		return fmt.Errorf("package build environment entry %q has unexpected name", name)
	}

	packageDir := path.Dir(cleanName)
	if packageDir == "." || packageDir == "/" || strings.Contains(packageDir, "/") {
		return fmt.Errorf("package build environment entry %q must be in the package directory root", name)
	}

	return nil
}

func validateBPMPackagePublicCertificateEntry(name string) error {
	name = strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if name == "" {
		return fmt.Errorf("package contains an empty path")
	}
	if path.IsAbs(name) {
		return fmt.Errorf("package public certificate entry %q must be relative", name)
	}
	for _, component := range strings.Split(name, "/") {
		if component == ".." {
			return fmt.Errorf("package public certificate entry %q escapes the package directory", name)
		}
	}

	cleanName := path.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return fmt.Errorf("package public certificate entry %q escapes the package directory", name)
	}
	if path.Base(cleanName) != defaultBPMBuildPublicCertificateFile {
		return fmt.Errorf("package public certificate entry %q has unexpected name", name)
	}

	packageDir := path.Dir(cleanName)
	if packageDir == "." || packageDir == "/" || strings.Contains(packageDir, "/") {
		return fmt.Errorf("package public certificate entry %q must be in the package directory root", name)
	}

	return nil
}

func parseBPMPackageManifest(body []byte, packageDir string) (bpmPackageManifest, error) {
	spec, err := parseBPMBuildSpec(body)
	if err != nil {
		return bpmPackageManifest{}, err
	}

	version, err := packageVersionFromDir(packageDir, spec.Metadata.Name)
	if err != nil {
		return bpmPackageManifest{}, err
	}

	manifest := bpmPackageManifest{
		Name:        spec.Metadata.Name,
		Version:     version,
		Description: spec.Metadata.Description,
		License:     spec.Metadata.License,
		Authors:     spec.Metadata.Authors,
		Upatches:    make([]bpmPackageUpatch, 0, len(spec.Upatches)),
	}
	for _, upatch := range spec.Upatches {
		loadPath, err := normalizeBPMArchivePath(upatch.LoadTarget, "upatches.load_target")
		if err != nil {
			return bpmPackageManifest{}, err
		}
		unloadPath, err := normalizeBPMArchivePath(upatch.UnloadTarget, "upatches.unload_target")
		if err != nil {
			return bpmPackageManifest{}, err
		}
		manifest.Upatches = append(manifest.Upatches, bpmPackageUpatch{
			LoadPath:   loadPath,
			UnloadPath: unloadPath,
		})
	}

	return manifest, nil
}

func packageVersionFromDir(packageDir string, name string) (string, error) {
	prefix := name + "-"
	if !strings.HasPrefix(packageDir, prefix) {
		return "", fmt.Errorf("package directory %q does not match package name %q", packageDir, name)
	}
	version := strings.TrimPrefix(packageDir, prefix)
	if _, err := normalizeBPMBuildVersion(version); err != nil {
		return "", fmt.Errorf("package directory version: %w", err)
	}

	return version, nil
}
