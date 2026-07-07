package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var bpmPackageVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

type bpmPackageFile struct {
	Target string
	Body   []byte
	Mode   int64
	Upatch bool
}

func buildBPMPackage(outputDir string, buildFile []byte, metadata bpmPackageMetadata, version string, files ...bpmPackageFile) (string, error) {
	version, err := normalizeBPMBuildVersion(version)
	if err != nil {
		return "", err
	}
	if len(buildFile) == 0 {
		return "", fmt.Errorf("build file is empty")
	}
	if outputDir == "" {
		outputDir = "."
	}

	packageDir := metadata.Name + "-" + version
	outputPath := filepath.Join(outputDir, packageDir+".bee")

	if err := writeBPMPackageArchive(outputPath, packageDir, buildFile, files); err != nil {
		return "", err
	}

	return outputPath, nil
}

func normalizeBPMBuildVersion(version string) (string, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return "", fmt.Errorf("package version is required")
	}
	if !bpmPackageVersionPattern.MatchString(version) {
		return "", fmt.Errorf("package version %q must contain only letters, numbers, dots, underscores, hyphens, and plus signs", version)
	}

	return version, nil
}

func writeBPMPackageArchive(outputPath string, packageDir string, buildFile []byte, files []bpmPackageFile) error {
	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create package %s: %w", outputPath, err)
	}
	defer out.Close()

	gzipWriter := gzip.NewWriter(out)
	tarWriter := tar.NewWriter(gzipWriter)

	modTime := time.Unix(0, 0)
	dirHeader := &tar.Header{
		Name:     packageDir + "/",
		Mode:     0o755,
		ModTime:  modTime,
		Typeflag: tar.TypeDir,
	}
	if err := tarWriter.WriteHeader(dirHeader); err != nil {
		return fmt.Errorf("write package directory: %w", err)
	}

	fileHeader := &tar.Header{
		Name:    path.Join(packageDir, defaultBPMBuildFile),
		Mode:    0o644,
		Size:    int64(len(buildFile)),
		ModTime: modTime,
	}
	if err := tarWriter.WriteHeader(fileHeader); err != nil {
		return fmt.Errorf("write Beefile header: %w", err)
	}
	if _, err := tarWriter.Write(buildFile); err != nil {
		return fmt.Errorf("write Beefile: %w", err)
	}
	for _, file := range files {
		mode := file.Mode
		if mode == 0 {
			mode = 0o644
		}
		fileHeader := &tar.Header{
			Name:    path.Join(packageDir, file.Target),
			Mode:    mode,
			Size:    int64(len(file.Body)),
			ModTime: modTime,
		}
		if err := tarWriter.WriteHeader(fileHeader); err != nil {
			return fmt.Errorf("write package file %s header: %w", file.Target, err)
		}
		if _, err := tarWriter.Write(file.Body); err != nil {
			return fmt.Errorf("write package file %s: %w", file.Target, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("close package tar: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("close package gzip: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close package %s: %w", outputPath, err)
	}

	return nil
}
