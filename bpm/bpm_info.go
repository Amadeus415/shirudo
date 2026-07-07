package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type bpmPackageInfo struct {
	Readme string
}

func infoBPMPackage(ctx context.Context, source string, httpClient *http.Client) (bpmPackageInfo, error) {
	archive, err := loadBPMPackageArchiveFromSource(ctx, source, httpClient)
	if err != nil {
		return bpmPackageInfo{}, err
	}

	readme, ok, err := readBPMPackageReadme(archive.Body)
	if err != nil {
		return bpmPackageInfo{}, err
	}
	if !ok {
		return bpmPackageInfo{}, fmt.Errorf("package %s does not include %s", source, defaultBPMReadmeFile)
	}

	return bpmPackageInfo{Readme: string(readme)}, nil
}

func fingerprintBPMPackage(ctx context.Context, source string, httpClient *http.Client) (string, error) {
	certificate, err := bpmPackagePublicCertificateFromSource(ctx, source, httpClient)
	if err != nil {
		return "", err
	}

	fingerprint, err := bpmSPKISHA256Fingerprint(certificate)
	if err != nil {
		return "", fmt.Errorf("fingerprint packaged Shirudo SPKI: %w", err)
	}

	return fingerprint, nil
}

func bpmPackagePublicCertificateFromSource(ctx context.Context, source string, httpClient *http.Client) ([]byte, error) {
	archive, err := loadBPMPackageArchiveFromSource(ctx, source, httpClient)
	if err != nil {
		return nil, err
	}

	certificate, ok, err := readBPMPackagePublicCertificate(archive.Body)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("package %s does not include %s", source, defaultBPMBuildPublicCertificateFile)
	}

	return certificate, nil
}

func loadBPMPackageArchiveFromSource(ctx context.Context, source string, httpClient *http.Client) (bpmPackageArchive, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return bpmPackageArchive{}, fmt.Errorf("package source is empty")
	}

	if strings.HasPrefix(source, bpmOCIScheme) {
		ref, err := parseBPMOCIReference(source)
		if err != nil {
			return bpmPackageArchive{}, err
		}

		client := newBPMOCIRegistryClient(ref.Repository.Registry, ref.Repository.Name, httpClient)
		body, _, err := client.pullPackage(ctx, ref)
		if err != nil {
			return bpmPackageArchive{}, err
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

	return loadBPMPackageArchive(source)
}
