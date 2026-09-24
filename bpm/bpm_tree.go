package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

const (
	bpmOCITreeMedia    = "application/vnd.shirudo.upatch.tree.v2+json"
	bpmOCITreeSigMedia = "application/vnd.shirudo.upatch.tree.signature.v2"
	bpmOCIUpatchMedia  = "application/vnd.shirudo.upatch.v1"
)

type bpmTreeSelector struct {
	Architecture        []string            `json:"architecture,omitempty"`
	Kconfig             map[string][]string `json:"kconfig,omitempty"`
	KernelBuildID       []string            `json:"kernel_build_id,omitempty"`
	KernelReleasePrefix []string            `json:"kernel_release_prefix,omitempty"`
	Labels              map[string][]string `json:"labels,omitempty"`
}

type bpmTreeArtifact struct {
	Repository     string `json:"repository"`
	ManifestDigest string `json:"manifest_digest"`
	LayerDigest    string `json:"layer_digest"`
	PayloadSHA256  string `json:"payload_sha256"`
}

type bpmTreeOperation struct {
	Seq             int64           `json:"seq"`
	Op              string          `json:"op"`
	ID              string          `json:"id"`
	Selector        bpmTreeSelector `json:"selector,omitempty"`
	Artifact        bpmTreeArtifact `json:"artifact"`
	OperationDigest string          `json:"operation_digest"`
}

type bpmTreeBase struct {
	Seq int64 `json:"seq"`
}

type bpmTreeHead struct {
	Seq int64 `json:"seq"`
}

type bpmTreePublication struct {
	Schema               int                `json:"schema"`
	TreeID               string             `json:"tree_id"`
	Generation           int64              `json:"generation"`
	ParentManifestDigest string             `json:"parent_manifest_digest,omitempty"`
	Base                 bpmTreeBase        `json:"base"`
	Operations           []bpmTreeOperation `json:"operations"`
	Head                 bpmTreeHead        `json:"head"`
}

type bpmTreeOperationHash struct {
	Seq      int64           `json:"seq"`
	Op       string          `json:"op"`
	ID       string          `json:"id"`
	Selector bpmTreeSelector `json:"selector,omitempty"`
	Artifact bpmTreeArtifact `json:"artifact"`
}

func bpmTreeHash(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func bpmTreeOperationDigest(op bpmTreeOperation) (string, error) {
	body, err := json.Marshal(bpmTreeOperationHash{
		Seq: op.Seq, Op: op.Op, ID: op.ID, Selector: op.Selector,
		Artifact: op.Artifact,
	})
	if err != nil {
		return "", err
	}
	return bpmTreeHash(body), nil
}

func readBPMArchiveEntry(packageBody []byte, relative string) ([]byte, error) {
	_, packageDir, err := readBPMPackageBeefile(packageBody)
	if err != nil {
		return nil, err
	}
	want := path.Join(packageDir, path.Clean(strings.ReplaceAll(relative, "\\", "/")))
	gzReader, err := gzipReaderForTree(packageBody)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()
	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if path.Clean(strings.ReplaceAll(header.Name, "\\", "/")) != want || header.Typeflag == tar.TypeDir {
			continue
		}
		return io.ReadAll(tarReader)
	}
	return nil, fmt.Errorf("package entry %s not found", relative)
}

// Kept as a small helper to avoid making the package archive reader expose
// its gzip implementation details to the rest of the publisher.
func gzipReaderForTree(body []byte) (*gzip.Reader, error) {
	return gzip.NewReader(bytes.NewReader(body))
}

func upatchPayloadSHA256(body []byte) (string, error) {
	if len(body) < 304 {
		return "", fmt.Errorf("upatch is shorter than its header")
	}
	return "sha256:" + hex.EncodeToString(body[272:304]), nil
}

func treeSelectorFromBuild(selector bpmBuildTreeSelector) bpmTreeSelector {
	result := bpmTreeSelector{
		KernelReleasePrefix: append([]string(nil), selector.KernelReleasePrefix...),
		KernelBuildID:       append([]string(nil), selector.KernelBuildID...),
		Architecture:        append([]string(nil), selector.Architecture...),
		Kconfig:             make(map[string][]string, len(selector.Kconfig)),
		Labels:              make(map[string][]string, len(selector.Labels)),
	}
	for key, values := range selector.Kconfig {
		result.Kconfig[key] = append([]string(nil), values...)
	}
	for key, values := range selector.Labels {
		result.Labels[key] = append([]string(nil), values...)
	}
	// Selector lists are sets for matching. Canonicalize their order before
	// hashing so equivalent Beefiles produce the same operation digest.
	sort.Strings(result.KernelReleasePrefix)
	sort.Strings(result.KernelBuildID)
	sort.Strings(result.Architecture)
	for key := range result.Kconfig {
		sort.Strings(result.Kconfig[key])
	}
	for key := range result.Labels {
		sort.Strings(result.Labels[key])
	}
	return result
}

func pushBPMTreeArtifact(ctx context.Context, client *bpmOCIRegistryClient,
	body []byte, id string, scope string) (bpmTreeArtifact, error) {
	payload, err := upatchPayloadSHA256(body)
	if err != nil {
		return bpmTreeArtifact{}, err
	}
	layer, err := client.pushBlob(ctx, body, bpmOCIUpatchMedia, scope)
	if err != nil {
		return bpmTreeArtifact{}, fmt.Errorf("push upatch artifact: %w", err)
	}
	config, err := client.pushBlob(ctx, []byte("{}"), bpmOCIEmptyConfigMediaType, scope)
	if err != nil {
		return bpmTreeArtifact{}, fmt.Errorf("push upatch artifact config: %w", err)
	}
	manifest := bpmOCIManifest{
		SchemaVersion: 2, MediaType: bpmOCIManifestMediaType,
		ArtifactType: bpmOCIUpatchMedia, Config: config,
		Layers:      []bpmOCIDescriptor{layer},
		Annotations: map[string]string{"org.opencontainers.image.title": id + ".upatch"},
	}
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		return bpmTreeArtifact{}, err
	}
	tag := "upatch-" + id + "-" + strings.TrimPrefix(payload, "sha256:")[:16]
	resp, err := client.do(ctx, http.MethodPut,
		client.url("/v2/"+client.repository+"/manifests/"+tag),
		manifestBody, bpmOCIManifestMediaType, bpmOCIManifestMediaType, scope)
	if err != nil {
		return bpmTreeArtifact{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return bpmTreeArtifact{}, responseError(resp, "push upatch artifact manifest")
	}
	return bpmTreeArtifact{
		Repository:     bpmOCIScheme + client.baseURL.Host + "/" + client.repository,
		ManifestDigest: digestBytes(manifestBody),
		LayerDigest:    layer.Digest,
		PayloadSHA256:  payload,
	}, nil
}

func pullBPMTreePublication(ctx context.Context, client *bpmOCIRegistryClient,
	reference string, certPath string) (bpmTreePublication, string, error) {
	scope := "repository:" + client.repository + ":pull"
	resp, err := client.do(ctx, http.MethodGet,
		client.url("/v2/"+client.repository+"/manifests/"+reference),
		nil, "", bpmOCIManifestMediaType, scope)
	if err != nil {
		return bpmTreePublication{}, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return bpmTreePublication{}, "", os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		return bpmTreePublication{}, "", responseError(resp, "read upatch tree manifest")
	}
	manifestBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return bpmTreePublication{}, "", err
	}
	var manifest bpmOCIManifest
	if err := json.Unmarshal(manifestBody, &manifest); err != nil {
		return bpmTreePublication{}, "", err
	}
	var payload, signature []byte
	for _, layer := range manifest.Layers {
		if layer.MediaType != bpmOCITreeMedia && layer.MediaType != bpmOCITreeSigMedia {
			continue
		}
		blobResp, err := client.do(ctx, http.MethodGet,
			client.url("/v2/"+client.repository+"/blobs/"+layer.Digest), nil,
			"", layer.MediaType, scope)
		if err != nil {
			return bpmTreePublication{}, "", err
		}
		body, readErr := io.ReadAll(blobResp.Body)
		blobResp.Body.Close()
		if readErr != nil {
			return bpmTreePublication{}, "", readErr
		}
		if digestBytes(body) != layer.Digest || (layer.Size >= 0 && layer.Size != int64(len(body))) {
			return bpmTreePublication{}, "", fmt.Errorf("upatch tree layer digest or size mismatch")
		}
		if layer.MediaType == bpmOCITreeMedia {
			payload = body
		} else {
			signature = body
		}
	}
	if len(payload) == 0 || len(signature) == 0 {
		return bpmTreePublication{}, "", fmt.Errorf("upatch tree manifest is missing payload or signature")
	}
	if err := verifyBPMIndex(ctx, payload, signature, certPath); err != nil {
		return bpmTreePublication{}, "", fmt.Errorf("verify upatch tree: %w", err)
	}
	var publication bpmTreePublication
	if err := json.Unmarshal(payload, &publication); err != nil {
		return bpmTreePublication{}, "", err
	}
	if publication.Schema != 2 || publication.TreeID == "" {
		return bpmTreePublication{}, "", fmt.Errorf("invalid upatch tree publication")
	}
	return publication, digestBytes(manifestBody), nil
}

func publishBPMTree(ctx context.Context, client *bpmOCIRegistryClient,
	publication bpmTreePublication, certPath, keyPath, reference string) error {
	payload, err := json.Marshal(publication)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "shirudo-upatch-tree-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	signature, err := signBPMIndex(ctx, tmpPath, certPath, keyPath)
	if err != nil {
		return err
	}
	scope := "repository:" + client.repository + ":pull,push"
	config, err := client.pushBlob(ctx, []byte("{}"), bpmOCIEmptyConfigMediaType, scope)
	if err != nil {
		return err
	}
	payloadLayer, err := client.pushBlob(ctx, payload, bpmOCITreeMedia, scope)
	if err != nil {
		return err
	}
	sigLayer, err := client.pushBlob(ctx, signature, bpmOCITreeSigMedia, scope)
	if err != nil {
		return err
	}
	manifestBody, err := json.Marshal(bpmOCIManifest{
		SchemaVersion: 2, MediaType: bpmOCIManifestMediaType,
		ArtifactType: "application/vnd.shirudo.upatch.tree.v2",
		Config:       config, Layers: []bpmOCIDescriptor{payloadLayer, sigLayer},
	})
	if err != nil {
		return err
	}
	resp, err := client.do(ctx, http.MethodPut,
		client.url("/v2/"+client.repository+"/manifests/"+reference),
		manifestBody, bpmOCIManifestMediaType, bpmOCIManifestMediaType, scope)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return responseError(resp, "publish upatch tree manifest")
	}
	return nil
}

func newStandaloneBPMTreeCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "tree", Short: "Publish signed append-only upatch trees", Args: cobra.NoArgs}
	cmd.AddCommand(newStandaloneBPMTreeAppendCommand())
	return cmd
}

func newStandaloneBPMTreeAppendCommand() *cobra.Command {
	var certPath, keyPath, treeID, reference, operation string
	cmd := &cobra.Command{
		Use:   "append <package-file> <repository>",
		Short: "Append the tree-enabled upatches in a package",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel, err := commandContext(cmd)
			if err != nil {
				return err
			}
			defer cancel()
			archive, err := loadBPMPackageArchive(args[0])
			if err != nil {
				return err
			}
			beefile, _, err := readBPMPackageBeefile(archive.Body)
			if err != nil {
				return err
			}
			spec, err := parseBPMBuildSpec(beefile)
			if err != nil {
				return err
			}
			if certPath == "" || keyPath == "" {
				return fmt.Errorf("--cert and --key are required")
			}
			if operation != "add" && operation != "delete" {
				return fmt.Errorf("--op must be add or delete")
			}
			if treeID != "" && !bpmPackageNamePattern.MatchString(treeID) {
				return fmt.Errorf("--tree-id %q is not a valid tree identifier", treeID)
			}
			repo, err := parseBPMOCIRepository(args[1])
			if err != nil {
				return err
			}
			client := newBPMOCIRegistryClient(repo.Registry, repo.Name, nil)
			scope := "repository:" + repo.Name + ":pull,push"
			publication, parent, err := pullBPMTreePublication(ctx, client, reference, certPath)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if os.IsNotExist(err) {
				publication = bpmTreePublication{Schema: 2, TreeID: treeID, Generation: 1,
					Base: bpmTreeBase{Seq: 0}, Operations: []bpmTreeOperation{}}
			} else {
				if treeID == "" {
					treeID = publication.TreeID
				}
				publication.Generation++
			}
			if treeID == "" {
				treeID = archive.Metadata.Name
			}
			if publication.TreeID != "" && publication.TreeID != treeID {
				return fmt.Errorf("tree id mismatch: existing %q, requested %q", publication.TreeID, treeID)
			}
			publication.TreeID = treeID
			for _, entry := range spec.Upatches {
				if entry.Tree == nil {
					continue
				}
				artifactPath := entry.Tree.LoadArtifact
				if operation == "delete" {
					artifactPath = entry.Tree.UnloadArtifact
				}
				body, err := readBPMArchiveEntry(archive.Body, artifactPath)
				if err != nil {
					return err
				}
				artifact, err := pushBPMTreeArtifact(ctx, client, body, entry.Tree.ID, scope)
				if err != nil {
					return err
				}
				artifact.Repository = args[1]
				op := bpmTreeOperation{Seq: publication.Head.Seq + 1, Op: operation, ID: entry.Tree.ID,
					Selector: treeSelectorFromBuild(entry.Tree.Selector), Artifact: artifact}
				op.OperationDigest, err = bpmTreeOperationDigest(op)
				if err != nil {
					return err
				}
				publication.Operations = append(publication.Operations, op)
				publication.Head.Seq = op.Seq
			}
			if len(publication.Operations) == 0 {
				return fmt.Errorf("package contains no tree-enabled upatches")
			}
			publication.ParentManifestDigest = parent
			return publishBPMTree(ctx, client, publication, certPath, keyPath, reference)
		},
	}
	cmd.Flags().StringVar(&certPath, "cert", "", "CMS signing certificate")
	cmd.Flags().StringVar(&keyPath, "key", "", "CMS signing private key")
	cmd.Flags().StringVar(&treeID, "tree-id", "", "tree identifier (defaults to package name)")
	cmd.Flags().StringVar(&reference, "reference", "stable", "OCI reference to update")
	cmd.Flags().StringVar(&operation, "op", "add", "operation to append: add or delete")
	return cmd
}
