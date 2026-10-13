package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	bpmOCIIndexRepository = "shirudo/bpm-index"
	bpmOCIIndexTag        = "stable"
	bpmOCIIndexMediaType  = "application/vnd.shirudo.bpm.index.v1+json"
	bpmOCIIndexSigMedia   = "application/vnd.shirudo.bpm.index.signature.v1"
)

type bpmOCIIndex struct {
	Schema      int                `json:"schema"`
	GeneratedAt string             `json:"generated_at"`
	Packages    []bpmOCIIndexEntry `json:"packages"`
}

type bpmOCIIndexEntry struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	Repository        string `json:"repository"`
	ManifestDigest    string `json:"manifest_digest"`
	PackageDigest     string `json:"package_digest"`
	PackageSize       int64  `json:"package_size"`
	SignerFingerprint string `json:"signer_fingerprint"`
}

func signBPMIndex(ctx context.Context, payloadPath, certPath, keyPath string) ([]byte, error) {
	dir := filepath.Dir(payloadPath)
	sigPath := filepath.Join(dir, "index.sig")
	// SHA-512 is explicit because ML-DSA keys have no default CMS digest
	// on OpenSSL 3.x, and it is the only digest the kernel's PKCS#7
	// parser accepts next to ML-DSA signed attributes; RSA keys sign the
	// same way, so one wire form covers both.
	args := []string{"cms", "-sign", "-binary", "-md", "sha512", "-in", payloadPath,
		"-signer", certPath, "-inkey", keyPath, "-out", sigPath,
		"-outform", "DER", "-nosmimecap"}
	cmd := exec.CommandContext(ctx, "openssl", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("sign repository index: %w: %s", err, strings.TrimSpace(string(out)))
	}
	body, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, fmt.Errorf("read repository index signature: %w", err)
	}
	return body, nil
}

func verifyBPMIndex(ctx context.Context, payload, signature []byte, certPath string) error {
	payloadFile, err := os.CreateTemp("", "shirudo-bpm-index-payload-*.json")
	if err != nil {
		return fmt.Errorf("stage repository index for verification: %w", err)
	}
	payloadPath := payloadFile.Name()
	defer os.Remove(payloadPath)
	signatureFile, err := os.CreateTemp("", "shirudo-bpm-index-signature-*.der")
	if err != nil {
		payloadFile.Close()
		return fmt.Errorf("stage repository index signature: %w", err)
	}
	signaturePath := signatureFile.Name()
	defer os.Remove(signaturePath)
	if _, err := payloadFile.Write(payload); err != nil {
		payloadFile.Close()
		signatureFile.Close()
		return fmt.Errorf("write repository index for verification: %w", err)
	}
	if err := payloadFile.Close(); err != nil {
		signatureFile.Close()
		return fmt.Errorf("close repository index for verification: %w", err)
	}
	if _, err := signatureFile.Write(signature); err != nil {
		signatureFile.Close()
		return fmt.Errorf("write repository index signature: %w", err)
	}
	if err := signatureFile.Close(); err != nil {
		return fmt.Errorf("close repository index signature: %w", err)
	}
	cmd := exec.CommandContext(ctx, "openssl", "cms", "-verify", "-binary",
		"-inform", "DER", "-in", signaturePath, "-content", payloadPath,
		"-CAfile", certPath, "-purpose", "any", "-out", os.DevNull)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("verify repository index signature: %w: %s", err,
			strings.TrimSpace(string(output)))
	}
	return nil
}

func validateBPMIndex(index bpmOCIIndex) error {
	if index.Schema != 1 {
		return fmt.Errorf("unsupported repository index schema %d", index.Schema)
	}
	for _, entry := range index.Packages {
		if entry.Name == "" || entry.Version == "" || entry.Repository == "" ||
			!strings.HasPrefix(entry.ManifestDigest, "sha256:") ||
			!strings.HasPrefix(entry.PackageDigest, "sha256:") || entry.PackageSize < 0 {
			return fmt.Errorf("repository index contains an invalid package entry")
		}
	}
	return nil
}

func updateBPMOCIIndex(ctx context.Context, registry, repository string,
	archive bpmPackageArchive, subject bpmOCIDescriptor,
	packageLayer bpmOCIDescriptor, signerFingerprint string,
	certPath, keyPath string, httpClient *http.Client) error {
	client := newBPMOCIRegistryClient(registry, bpmOCIIndexRepository, httpClient)
	index := bpmOCIIndex{Schema: 1, Packages: []bpmOCIIndexEntry{}}

	manifestPath := "/v2/" + bpmOCIIndexRepository + "/manifests/" + bpmOCIIndexTag
	resp, err := client.do(ctx, http.MethodGet, client.url(manifestPath), nil, "", bpmOCIManifestMediaType, "repository:"+bpmOCIIndexRepository+":pull,push")
	if err == nil && resp.StatusCode == http.StatusOK {
		var manifest bpmOCIManifest
		if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
			resp.Body.Close()
			return fmt.Errorf("decode repository index manifest: %w", err)
		}
		resp.Body.Close()
		var indexPayload, indexSignature []byte
		for _, layer := range manifest.Layers {
			if layer.MediaType != bpmOCIIndexMediaType {
				if layer.MediaType != bpmOCIIndexSigMedia {
					continue
				}
			}
			blobResp, err := client.do(ctx, http.MethodGet,
				client.url("/v2/"+bpmOCIIndexRepository+"/blobs/"+layer.Digest),
				nil, "", bpmOCIIndexMediaType,
				"repository:"+bpmOCIIndexRepository+":pull,push")
			if err != nil {
				return fmt.Errorf("download existing repository index: %w", err)
			}
			body, readErr := ioReadAllLimit(blobResp.Body, 64*1024*1024)
			blobResp.Body.Close()
			if readErr != nil {
				return readErr
			}
			if layer.Size >= 0 && layer.Size != int64(len(body)) {
				return fmt.Errorf("existing repository index layer size mismatch")
			}
			if digestBytes(body) != layer.Digest {
				return fmt.Errorf("existing repository index layer digest mismatch")
			}
			if layer.MediaType == bpmOCIIndexMediaType {
				indexPayload = body
			} else {
				indexSignature = body
			}
		}
		if len(indexPayload) == 0 || len(indexSignature) == 0 {
			return fmt.Errorf("existing repository index is missing payload or signature")
		}
		if err := verifyBPMIndex(ctx, indexPayload, indexSignature, certPath); err != nil {
			return err
		}
		if err := json.Unmarshal(indexPayload, &index); err != nil {
			return fmt.Errorf("decode existing repository index: %w", err)
		}
		if err := validateBPMIndex(index); err != nil {
			return err
		}
	} else if err == nil && resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
	} else if err == nil {
		defer resp.Body.Close()
		return responseError(resp, "read existing repository index")
	} else {
		return fmt.Errorf("read existing repository index: %w", err)
	}

	if index.Schema == 0 {
		index.Schema = 1
	}
	entry := bpmOCIIndexEntry{
		Name: archive.Metadata.Name, Version: archive.Metadata.Version,
		Repository: repository, ManifestDigest: subject.Digest,
		PackageDigest: packageLayer.Digest, PackageSize: packageLayer.Size,
		SignerFingerprint: signerFingerprint,
	}
	found := false
	for i := range index.Packages {
		if index.Packages[i].Name != entry.Name || index.Packages[i].Version != entry.Version {
			continue
		}
		if index.Packages[i].ManifestDigest != entry.ManifestDigest || index.Packages[i].PackageDigest != entry.PackageDigest {
			return fmt.Errorf("repository index already contains conflicting %s/%s", entry.Name, entry.Version)
		}
		index.Packages[i] = entry
		found = true
	}
	if !found {
		index.Packages = append(index.Packages, entry)
	}
	if err := validateBPMIndex(index); err != nil {
		return err
	}
	sort.Slice(index.Packages, func(i, j int) bool {
		if index.Packages[i].Name != index.Packages[j].Name {
			return index.Packages[i].Name < index.Packages[j].Name
		}
		return index.Packages[i].Version < index.Packages[j].Version
	})
	index.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	payload, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("encode repository index: %w", err)
	}
	tmp, err := os.CreateTemp("", "shirudo-bpm-index-*.json")
	if err != nil {
		return fmt.Errorf("create repository index staging file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return fmt.Errorf("write repository index: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close repository index: %w", err)
	}
	signature, err := signBPMIndex(ctx, tmpPath, certPath, keyPath)
	if err != nil {
		return err
	}
	scope := "repository:" + bpmOCIIndexRepository + ":pull,push"
	config, err := client.pushBlob(ctx, []byte("{}"), bpmOCIEmptyConfigMediaType, scope)
	if err != nil {
		return fmt.Errorf("push index config: %w", err)
	}
	indexLayer, err := client.pushBlob(ctx, payload, bpmOCIIndexMediaType, scope)
	if err != nil {
		return fmt.Errorf("push index payload: %w", err)
	}
	sigLayer, err := client.pushBlob(ctx, signature, bpmOCIIndexSigMedia, scope)
	if err != nil {
		return fmt.Errorf("push index signature: %w", err)
	}
	manifest := bpmOCIManifest{
		SchemaVersion: 2, MediaType: bpmOCIManifestMediaType,
		ArtifactType: "application/vnd.shirudo.bpm.index.v1",
		Config:       config, Layers: []bpmOCIDescriptor{indexLayer, sigLayer},
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode repository index manifest: %w", err)
	}
	resp, err = client.do(ctx, http.MethodPut, client.url(manifestPath), body,
		bpmOCIManifestMediaType, bpmOCIManifestMediaType, scope)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return responseError(resp, "push repository index manifest")
	}
	return nil
}

func ioReadAllLimit(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err == nil && int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return body, err
}

func putBPMPackageWithIndex(ctx context.Context, packagePath, repository,
	certPath, keyPath string, httpClient *http.Client) (string, error) {
	if (strings.TrimSpace(certPath) == "") != (strings.TrimSpace(keyPath) == "") {
		return "", fmt.Errorf("--index-cert and --index-key must be supplied together")
	}
	ref, err := putBPMPackage(ctx, packagePath, repository, httpClient)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return ref, nil
	}
	archive, err := loadBPMPackageArchive(packagePath)
	if err != nil {
		return "", err
	}
	parsed, err := parseBPMOCIReference(ref)
	if err != nil {
		return "", err
	}
	client := newBPMOCIRegistryClient(parsed.Repository.Registry, parsed.Repository.Name, httpClient)
	resp, err := client.do(ctx, http.MethodGet,
		client.url("/v2/"+parsed.Repository.Name+"/manifests/"+parsed.Tag),
		nil, "", bpmOCIManifestMediaType, "repository:"+parsed.Repository.Name+":pull")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", responseError(resp, "read pushed package manifest")
	}
	body, err := ioReadAllLimit(resp.Body, 4*1024*1024)
	if err != nil {
		return "", err
	}
	var manifest bpmOCIManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return "", err
	}
	layer, err := packageLayerFromManifest(manifest)
	if err != nil {
		return "", err
	}
	cert, err := bpmPackagePublicCertificate(packagePath, archive)
	if err != nil {
		return "", err
	}
	fingerprint, err := bpmSPKISHA256Fingerprint(cert.Body)
	if err != nil {
		return "", err
	}
	if err := updateBPMOCIIndex(ctx, parsed.Repository.Registry, parsed.Repository.Name,
		archive, bpmOCIDescriptor{MediaType: bpmOCIManifestMediaType,
			Digest: digestBytes(body), Size: int64(len(body))},
		layer, fingerprint, certPath, keyPath, httpClient); err != nil {
		return "", err
	}
	return ref, nil
}
