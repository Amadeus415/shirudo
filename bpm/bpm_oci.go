package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

const (
	bpmOCIScheme                = "oci://"
	bpmOCIManifestMediaType     = "application/vnd.oci.image.manifest.v1+json"
	bpmOCIEmptyConfigMediaType  = "application/vnd.oci.empty.v1+json"
	bpmOCIConfigMediaType       = "application/vnd.shirudo.bpm.config.v1+json"
	bpmOCIPackageLayerMediaType = "application/vnd.shirudo.bpm.package.v1+gzip"
	bpmOCIPublicKeyArtifactType = "application/vnd.shirudo.bpm.public-key.v1+der"
	bpmOCIPublicKeyMediaType    = "application/pkix-cert"
)

type bpmOCIRepository struct {
	Registry string
	Name     string
}

type bpmOCIReference struct {
	Repository bpmOCIRepository
	Tag        string
}

func putBPMPackage(ctx context.Context, packagePath string, repository string, httpClient *http.Client) (string, error) {
	archive, err := loadBPMPackageArchive(packagePath)
	if err != nil {
		return "", err
	}
	publicCertificate, err := bpmPackagePublicCertificate(packagePath, archive)
	if err != nil {
		return "", err
	}

	repo, err := parseBPMOCIRepository(repository)
	if err != nil {
		return "", err
	}

	client := newBPMOCIRegistryClient(repo.Registry, repo.Name, httpClient)
	subject, err := client.pushPackage(ctx, archive, filepath.Base(packagePath))
	if err != nil {
		return "", err
	}
	if err := client.attachPublicCertificate(ctx, subject, publicCertificate); err != nil {
		return "", err
	}

	return repo.reference(archive.Metadata.Version), nil
}

type bpmPublicCertificate struct {
	Body []byte
}

func bpmPackagePublicCertificate(packagePath string, archive bpmPackageArchive) (bpmPublicCertificate, error) {
	environment, ok, err := readBPMPackageBuildEnvironment(archive.Body)
	if err != nil {
		return bpmPublicCertificate{}, err
	}
	if !ok {
		return bpmPublicCertificate{}, fmt.Errorf("package %s does not include %s; rebuild with bpm build --keys-dir <dir>", packagePath, defaultBPMBuildEnvironmentFile)
	}

	body, ok, err := readBPMPackagePublicCertificate(archive.Body)
	if err != nil {
		return bpmPublicCertificate{}, err
	}
	if !ok {
		return bpmPublicCertificate{}, fmt.Errorf("package %s does not include %s; rebuild with bpm build --keys-dir <dir>", packagePath, defaultBPMBuildPublicCertificateFile)
	}
	fingerprint, err := bpmSPKISHA256Fingerprint(body)
	if err != nil {
		return bpmPublicCertificate{}, fmt.Errorf("fingerprint packaged Shirudo SPKI: %w", err)
	}
	want := strings.TrimSpace(environment.Shirudo.SPKISHA256Fingerprint)
	if want != "" && !strings.EqualFold(fingerprint, want) {
		return bpmPublicCertificate{}, fmt.Errorf("Shirudo SPKI fingerprint mismatch: got %s from package %s, package records %s", fingerprint, defaultBPMBuildPublicCertificateFile, want)
	}

	return bpmPublicCertificate{
		Body: body,
	}, nil
}

func getBPMPackage(ctx context.Context, rawReference string, outputDir string, httpClient *http.Client) (string, error) {
	ref, err := parseBPMOCIReference(rawReference)
	if err != nil {
		return "", err
	}

	client := newBPMOCIRegistryClient(ref.Repository.Registry, ref.Repository.Name, httpClient)
	body, filename, err := client.pullPackage(ctx, ref)
	if err != nil {
		return "", err
	}
	if outputDir == "" {
		outputDir = "."
	}

	outputPath := filepath.Join(outputDir, filename)
	if err := os.WriteFile(outputPath, body, 0o644); err != nil {
		return "", fmt.Errorf("write package file %s: %w", outputPath, err)
	}

	return outputPath, nil
}

func parseBPMOCIRepository(raw string) (bpmOCIRepository, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return bpmOCIRepository{}, fmt.Errorf("repository is empty")
	}
	if !strings.HasPrefix(raw, bpmOCIScheme) {
		return bpmOCIRepository{}, fmt.Errorf("repository must start with %s", bpmOCIScheme)
	}

	withoutScheme := strings.TrimPrefix(raw, bpmOCIScheme)
	if strings.Contains(withoutScheme, "://") {
		return bpmOCIRepository{}, fmt.Errorf("repository must use only the %s scheme", strings.TrimSuffix(bpmOCIScheme, "://"))
	}
	if strings.Contains(withoutScheme, "@") {
		return bpmOCIRepository{}, fmt.Errorf("repository must not include a digest")
	}

	registry, name, ok := strings.Cut(withoutScheme, "/")
	if !ok || strings.TrimSpace(registry) == "" || strings.TrimSpace(name) == "" {
		return bpmOCIRepository{}, fmt.Errorf("repository must be %s<registry>/<name>", bpmOCIScheme)
	}
	if strings.Contains(name, ":") {
		return bpmOCIRepository{}, fmt.Errorf("repository must not include a tag")
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" {
			return bpmOCIRepository{}, fmt.Errorf("repository name contains an empty path component")
		}
	}

	return bpmOCIRepository{
		Registry: registry,
		Name:     name,
	}, nil
}

func parseBPMOCIReference(raw string) (bpmOCIReference, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return bpmOCIReference{}, fmt.Errorf("package reference is empty")
	}
	if !strings.HasPrefix(raw, bpmOCIScheme) {
		return bpmOCIReference{}, fmt.Errorf("package reference must start with %s", bpmOCIScheme)
	}
	if strings.Contains(raw, "@") {
		return bpmOCIReference{}, fmt.Errorf("package reference must use a tag, not a digest")
	}

	withoutScheme := strings.TrimPrefix(raw, bpmOCIScheme)
	lastSlash := strings.LastIndex(withoutScheme, "/")
	lastColon := strings.LastIndex(withoutScheme, ":")
	if lastColon <= lastSlash {
		return bpmOCIReference{}, fmt.Errorf("package reference must include a tag")
	}

	repository, tag := withoutScheme[:lastColon], withoutScheme[lastColon+1:]
	if strings.TrimSpace(tag) == "" {
		return bpmOCIReference{}, fmt.Errorf("package reference tag is empty")
	}
	if _, err := normalizeBPMBuildVersion(tag); err != nil {
		return bpmOCIReference{}, fmt.Errorf("package reference tag: %w", err)
	}

	repo, err := parseBPMOCIRepository(bpmOCIScheme + repository)
	if err != nil {
		return bpmOCIReference{}, err
	}

	return bpmOCIReference{
		Repository: repo,
		Tag:        tag,
	}, nil
}

func (repo bpmOCIRepository) reference(tag string) string {
	return bpmOCIScheme + repo.Registry + "/" + repo.Name + ":" + tag
}

type bpmOCIRegistryClient struct {
	baseURL      *url.URL
	httpClient   *http.Client
	initErr      error
	repository   string
	credentials  bpmRegistryCredentials
	token        string
	useBasicAuth bool
}

type bpmRegistryCredentials struct {
	username string
	password string
}

var bpmDockerCredentialHelperGet = runBPMDockerCredentialHelperGet

func newBPMOCIRegistryClient(registry string, repository string, httpClient *http.Client) *bpmOCIRegistryClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	configuredClient, err := configureBPMOCIHTTPClient(httpClient)
	if err == nil {
		httpClient = configuredClient
	}

	credentials, _ := findBPMRegistryCredentials(registry)
	return &bpmOCIRegistryClient{
		baseURL:     bpmRegistryBaseURL(registry),
		httpClient:  httpClient,
		initErr:     err,
		repository:  repository,
		credentials: credentials,
	}
}

func bpmRegistryBaseURL(registry string) *url.URL {
	scheme := strings.TrimSpace(os.Getenv("BPM_OCI_SCHEME"))
	if scheme == "" {
		scheme = "https"
		if strings.HasPrefix(registry, "localhost:") || strings.HasPrefix(registry, "127.0.0.1:") {
			scheme = "http"
		}
	}

	return &url.URL{
		Scheme: scheme,
		Host:   registry,
	}
}

// configureBPMOCIHTTPClient applies shirudo's TLS policy to the registry
// client, matching the libcurl clients in the C tree: TLS 1.3 only and
// the hybrid X25519MLKEM768 key exchange only, so neither a version
// downgrade nor a classical group can be negotiated. BPM_OCI_CA_FILE adds
// a trust anchor.
// A client with an opaque RoundTripper (tests) is left untouched unless a
// CA file is requested, which cannot be honoured there.
func configureBPMOCIHTTPClient(client *http.Client) (*http.Client, error) {
	scheme := strings.TrimSpace(os.Getenv("BPM_OCI_SCHEME"))
	if scheme != "" && scheme != "https" && scheme != "http" {
		return client, fmt.Errorf("BPM_OCI_SCHEME must be https or http, got %q", scheme)
	}
	caPath := strings.TrimSpace(os.Getenv("BPM_OCI_CA_FILE"))

	transport, ok := client.Transport.(*http.Transport)
	if !ok && client.Transport == nil {
		transport, ok = http.DefaultTransport.(*http.Transport)
	}
	if !ok {
		if caPath == "" {
			return client, nil
		}
		return client, fmt.Errorf("BPM_OCI_CA_FILE requires an HTTP TLS transport")
	}
	transport = transport.Clone()
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	} else {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.MinVersion = tls.VersionTLS13
	transport.TLSClientConfig.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}

	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return client, fmt.Errorf("read BPM_OCI_CA_FILE %s: %w", caPath, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if pool == nil || !pool.AppendCertsFromPEM(caPEM) {
			return client, fmt.Errorf("BPM_OCI_CA_FILE %s does not contain a valid PEM CA certificate", caPath)
		}
		transport.TLSClientConfig.RootCAs = pool
	}

	configured := *client
	configured.Transport = transport
	return &configured, nil
}

func (client *bpmOCIRegistryClient) pushPackage(ctx context.Context, archive bpmPackageArchive, filename string) (bpmOCIDescriptor, error) {
	scope := "repository:" + client.repository + ":pull,push"
	configBody := []byte(`{"mediaType":"` + bpmOCIConfigMediaType + `"}`)
	configDescriptor, err := client.pushBlob(ctx, configBody, bpmOCIConfigMediaType, scope)
	if err != nil {
		return bpmOCIDescriptor{}, fmt.Errorf("push package config: %w", err)
	}

	layerDescriptor, err := client.pushBlob(ctx, archive.Body, bpmOCIPackageLayerMediaType, scope)
	if err != nil {
		return bpmOCIDescriptor{}, fmt.Errorf("push package blob: %w", err)
	}
	layerDescriptor.Annotations = map[string]string{
		"org.opencontainers.image.title": filename,
	}

	manifest := bpmOCIManifest{
		SchemaVersion: 2,
		MediaType:     bpmOCIManifestMediaType,
		Config:        configDescriptor,
		Layers:        []bpmOCIDescriptor{layerDescriptor},
		Annotations: map[string]string{
			"dev.shirudo.bpm.package.name":     archive.Metadata.Name,
			"dev.shirudo.bpm.package.version":  archive.Metadata.Version,
			"org.opencontainers.image.title":   archive.Metadata.Name,
			"org.opencontainers.image.version": archive.Metadata.Version,
		},
	}
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		return bpmOCIDescriptor{}, fmt.Errorf("encode package manifest: %w", err)
	}

	manifestPath := "/v2/" + client.repository + "/manifests/" + archive.Metadata.Version
	resp, err := client.do(ctx, http.MethodPut, client.url(manifestPath), manifestBody, bpmOCIManifestMediaType, bpmOCIManifestMediaType, scope)
	if err != nil {
		return bpmOCIDescriptor{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return bpmOCIDescriptor{}, responseError(resp, "push package manifest")
	}

	return bpmOCIDescriptor{
		MediaType: bpmOCIManifestMediaType,
		Digest:    digestBytes(manifestBody),
		Size:      int64(len(manifestBody)),
	}, nil
}

func (client *bpmOCIRegistryClient) attachPublicCertificate(ctx context.Context, subject bpmOCIDescriptor, certificate bpmPublicCertificate) error {
	scope := "repository:" + client.repository + ":pull,push"
	configBody := []byte("{}")
	configDescriptor, err := client.pushBlob(ctx, configBody, bpmOCIEmptyConfigMediaType, scope)
	if err != nil {
		return fmt.Errorf("push public key config: %w", err)
	}

	layerDescriptor, err := client.pushBlob(ctx, certificate.Body, bpmOCIPublicKeyMediaType, scope)
	if err != nil {
		return fmt.Errorf("push public key blob: %w", err)
	}

	manifest := bpmOCIManifest{
		SchemaVersion: 2,
		MediaType:     bpmOCIManifestMediaType,
		ArtifactType:  bpmOCIPublicKeyArtifactType,
		Config:        configDescriptor,
		Layers:        []bpmOCIDescriptor{layerDescriptor},
		Subject:       &subject,
	}
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode public key manifest: %w", err)
	}

	manifestPath := "/v2/" + client.repository + "/manifests/" + digestBytes(manifestBody)
	resp, err := client.do(ctx, http.MethodPut, client.url(manifestPath), manifestBody, bpmOCIManifestMediaType, bpmOCIManifestMediaType, scope)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return responseError(resp, "attach public key manifest")
	}

	return nil
}

func (client *bpmOCIRegistryClient) pushBlob(ctx context.Context, body []byte, mediaType string, scope string) (bpmOCIDescriptor, error) {
	descriptor := bpmOCIDescriptor{
		MediaType: mediaType,
		Digest:    digestBytes(body),
		Size:      int64(len(body)),
	}

	headPath := "/v2/" + client.repository + "/blobs/" + descriptor.Digest
	resp, err := client.do(ctx, http.MethodHead, client.url(headPath), nil, "", "", scope)
	if err != nil {
		return bpmOCIDescriptor{}, err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return descriptor, nil
	}
	if resp.StatusCode != http.StatusNotFound {
		return bpmOCIDescriptor{}, responseError(resp, "check package blob")
	}

	startPath := "/v2/" + client.repository + "/blobs/uploads/"
	resp, err = client.do(ctx, http.MethodPost, client.url(startPath), nil, "", "", scope)
	if err != nil {
		return bpmOCIDescriptor{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return bpmOCIDescriptor{}, responseError(resp, "start package blob upload")
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return bpmOCIDescriptor{}, fmt.Errorf("start package blob upload: registry response missing Location header")
	}
	uploadURL, err := resp.Request.URL.Parse(location)
	if err != nil {
		return bpmOCIDescriptor{}, fmt.Errorf("parse package blob upload location: %w", err)
	}
	if uploadURL.Scheme != client.baseURL.Scheme ||
		uploadURL.Host != client.baseURL.Host {
		return bpmOCIDescriptor{}, fmt.Errorf("reject package blob upload location on different origin %s", uploadURL.Redacted())
	}
	query := uploadURL.Query()
	query.Set("digest", descriptor.Digest)
	uploadURL.RawQuery = query.Encode()

	resp, err = client.do(ctx, http.MethodPut, uploadURL, body, "application/octet-stream", "", scope)
	if err != nil {
		return bpmOCIDescriptor{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return bpmOCIDescriptor{}, responseError(resp, "finish package blob upload")
	}

	return descriptor, nil
}

func (client *bpmOCIRegistryClient) pullPackage(ctx context.Context, ref bpmOCIReference) ([]byte, string, error) {
	scope := "repository:" + client.repository + ":pull"
	manifestPath := "/v2/" + client.repository + "/manifests/" + ref.Tag
	resp, err := client.do(ctx, http.MethodGet, client.url(manifestPath), nil, "", bpmOCIManifestMediaType, scope)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", responseError(resp, "pull package manifest")
	}

	var manifest bpmOCIManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, "", fmt.Errorf("decode package manifest: %w", err)
	}
	layer, err := packageLayerFromManifest(manifest)
	if err != nil {
		return nil, "", err
	}

	blobPath := "/v2/" + client.repository + "/blobs/" + layer.Digest
	resp, err = client.do(ctx, http.MethodGet, client.url(blobPath), nil, "", layer.MediaType, scope)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", responseError(resp, "pull package blob")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read package blob: %w", err)
	}
	if digest := digestBytes(body); digest != layer.Digest {
		return nil, "", fmt.Errorf("package blob digest mismatch: got %s, want %s", digest, layer.Digest)
	}
	if layer.Size >= 0 && int64(len(body)) != layer.Size {
		return nil, "", fmt.Errorf("package blob size mismatch: got %d, want %d", len(body), layer.Size)
	}

	filename, err := packageFilenameFromManifest(ref, manifest, layer)
	if err != nil {
		return nil, "", err
	}

	return body, filename, nil
}

func packageLayerFromManifest(manifest bpmOCIManifest) (bpmOCIDescriptor, error) {
	for _, layer := range manifest.Layers {
		if layer.MediaType == bpmOCIPackageLayerMediaType {
			return layer, nil
		}
	}

	return bpmOCIDescriptor{}, fmt.Errorf("package manifest missing %s layer", bpmOCIPackageLayerMediaType)
}

func packageFilenameFromManifest(ref bpmOCIReference, manifest bpmOCIManifest, layer bpmOCIDescriptor) (string, error) {
	if title := strings.TrimSpace(layer.Annotations["org.opencontainers.image.title"]); title != "" {
		filename := filepath.Base(title)
		if filename == title && strings.HasSuffix(filename, ".bee") {
			return filename, nil
		}
	}

	name := strings.TrimSpace(manifest.Annotations["dev.shirudo.bpm.package.name"])
	if name == "" {
		name = path.Base(ref.Repository.Name)
	}
	if !bpmPackageNamePattern.MatchString(name) {
		return "", fmt.Errorf("package name %q cannot be used as a filename", name)
	}

	return name + "-" + ref.Tag + ".bee", nil
}

func (client *bpmOCIRegistryClient) url(requestPath string) *url.URL {
	next := *client.baseURL
	next.Path = path.Join(next.Path, requestPath)
	if strings.HasSuffix(requestPath, "/") && !strings.HasSuffix(next.Path, "/") {
		next.Path += "/"
	}
	return &next
}

func (client *bpmOCIRegistryClient) do(ctx context.Context, method string, requestURL *url.URL, body []byte, contentType string, accept string, scope string) (*http.Response, error) {
	if client.initErr != nil {
		return nil, client.initErr
	}
	resp, err := client.doOnce(ctx, method, requestURL, body, contentType, accept)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	challengeHeader := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	if challengeHeader == "" {
		return resp, fmt.Errorf("%s %s: unauthorized", method, requestURL.String())
	}
	if err := client.authorize(ctx, challengeHeader, scope); err != nil {
		return nil, err
	}

	return client.doOnce(ctx, method, requestURL, body, contentType, accept)
}

func (client *bpmOCIRegistryClient) doOnce(ctx context.Context, method string, requestURL *url.URL, body []byte, contentType string, accept string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), reader)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	if client.token != "" {
		request.Header.Set("Authorization", "Bearer "+client.token)
	} else if client.useBasicAuth {
		request.SetBasicAuth(client.credentials.username, client.credentials.password)
	}

	return client.httpClient.Do(request)
}

func (client *bpmOCIRegistryClient) authorize(ctx context.Context, challengeHeader string, scope string) error {
	scheme, params := parseBPMWWWAuthenticate(challengeHeader)
	switch strings.ToLower(scheme) {
	case "bearer":
		token, err := client.fetchBearerToken(ctx, params, scope)
		if err != nil {
			return err
		}
		client.token = token
		return nil
	case "basic":
		if client.credentials.username == "" {
			return fmt.Errorf("registry requires basic auth, but no credentials were found")
		}
		client.useBasicAuth = true
		return nil
	default:
		return fmt.Errorf("unsupported registry auth challenge %q", scheme)
	}
}

func (client *bpmOCIRegistryClient) fetchBearerToken(ctx context.Context, params map[string]string, scope string) (string, error) {
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("registry bearer auth challenge missing realm")
	}

	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("parse registry bearer realm: %w", err)
	}
	query := tokenURL.Query()
	if service := params["service"]; service != "" {
		query.Set("service", service)
	}
	if challengeScope := params["scope"]; challengeScope != "" {
		query.Set("scope", challengeScope)
	} else if scope != "" {
		query.Set("scope", scope)
	}
	tokenURL.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	if client.credentials.username != "" {
		request.SetBasicAuth(client.credentials.username, client.credentials.password)
	}

	resp, err := client.httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", responseError(resp, "fetch registry token")
	}

	var tokenResponse struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("decode registry token response: %w", err)
	}
	if tokenResponse.Token != "" {
		return tokenResponse.Token, nil
	}
	if tokenResponse.AccessToken != "" {
		return tokenResponse.AccessToken, nil
	}

	return "", fmt.Errorf("registry token response missing token")
}

func parseBPMWWWAuthenticate(header string) (string, map[string]string) {
	header = strings.TrimSpace(header)
	scheme, rest, _ := strings.Cut(header, " ")
	params := map[string]string{}
	for rest != "" {
		rest = strings.TrimSpace(rest)
		key, value, found := strings.Cut(rest, "=")
		if !found {
			break
		}
		key = strings.TrimSpace(strings.TrimSuffix(key, ","))
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, `"`) {
			parsed, tail, err := parseBPMQuotedAuthValue(value)
			if err != nil {
				break
			}
			params[key] = parsed
			rest = strings.TrimPrefix(strings.TrimSpace(tail), ",")
			continue
		}
		raw, tail, _ := strings.Cut(value, ",")
		params[key] = strings.TrimSpace(raw)
		rest = tail
	}

	return scheme, params
}

func parseBPMQuotedAuthValue(value string) (string, string, error) {
	escaped := false
	for i := 1; i < len(value); i++ {
		switch {
		case escaped:
			escaped = false
		case value[i] == '\\':
			escaped = true
		case value[i] == '"':
			parsed, err := strconvUnquote(value[:i+1])
			if err != nil {
				return "", "", err
			}
			return parsed, value[i+1:], nil
		}
	}

	return "", "", fmt.Errorf("unterminated quoted auth value")
}

func strconvUnquote(value string) (string, error) {
	var parsed string
	if err := json.Unmarshal([]byte(value), &parsed); err != nil {
		return "", err
	}
	return parsed, nil
}

type bpmOCIDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type bpmOCIManifest struct {
	SchemaVersion int                `json:"schemaVersion"`
	MediaType     string             `json:"mediaType"`
	ArtifactType  string             `json:"artifactType,omitempty"`
	Config        bpmOCIDescriptor   `json:"config"`
	Layers        []bpmOCIDescriptor `json:"layers"`
	Subject       *bpmOCIDescriptor  `json:"subject,omitempty"`
	Annotations   map[string]string  `json:"annotations,omitempty"`
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func responseError(resp *http.Response, action string) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = resp.Status
	}

	return fmt.Errorf("%s: %s", action, message)
}

func findBPMRegistryCredentials(registry string) (bpmRegistryCredentials, bool) {
	for _, path := range registryAuthFilePaths() {
		credentials, ok := readBPMRegistryCredentials(path, registry)
		if ok {
			return credentials, true
		}
	}

	return bpmRegistryCredentials{}, false
}

func registryAuthFilePaths() []string {
	var paths []string
	if dockerConfig := os.Getenv("DOCKER_CONFIG"); dockerConfig != "" {
		paths = append(paths, filepath.Join(dockerConfig, "config.json"))
	}
	if registryAuthFile := os.Getenv("REGISTRY_AUTH_FILE"); registryAuthFile != "" {
		paths = append(paths, registryAuthFile)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".docker", "config.json"),
			filepath.Join(home, ".config", "containers", "auth.json"),
		)
	}

	return paths
}

func readBPMRegistryCredentials(path string, registry string) (bpmRegistryCredentials, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return bpmRegistryCredentials{}, false
	}

	var config struct {
		Auths map[string]struct {
			Auth     string `json:"auth"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"auths"`
		CredsStore  string            `json:"credsStore"`
		CredHelpers map[string]string `json:"credHelpers"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		return bpmRegistryCredentials{}, false
	}

	for _, key := range []string{registry, "https://" + registry, "http://" + registry} {
		entry, ok := config.Auths[key]
		if !ok {
			continue
		}
		if entry.Username != "" {
			return bpmRegistryCredentials{username: entry.Username, password: entry.Password}, true
		}
		if entry.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err != nil {
				return bpmRegistryCredentials{}, false
			}
			username, password, ok := strings.Cut(string(decoded), ":")
			if !ok {
				return bpmRegistryCredentials{}, false
			}
			return bpmRegistryCredentials{username: username, password: password}, true
		}
	}

	if helperName := dockerCredentialHelperName(config.CredHelpers, config.CredsStore, registry); helperName != "" {
		return bpmDockerCredentialHelperGet(helperName, registry)
	}

	return bpmRegistryCredentials{}, false
}

func dockerCredentialHelperName(credHelpers map[string]string, credsStore string, registry string) string {
	for _, key := range []string{registry, "https://" + registry, "http://" + registry} {
		if helperName := strings.TrimSpace(credHelpers[key]); helperName != "" {
			return helperName
		}
	}

	return strings.TrimSpace(credsStore)
}

func runBPMDockerCredentialHelperGet(helperName string, registry string) (bpmRegistryCredentials, bool) {
	for _, serverURL := range dockerCredentialServerURLs(registry) {
		credentials, ok := runBPMDockerCredentialHelperGetForServerURL(helperName, serverURL)
		if ok {
			return credentials, true
		}
	}

	return bpmRegistryCredentials{}, false
}

func runBPMDockerCredentialHelperGetForServerURL(helperName string, serverURL string) (bpmRegistryCredentials, bool) {
	command := exec.Command("docker-credential-"+helperName, "get")
	command.Stdin = strings.NewReader(serverURL)

	out, err := command.Output()
	if err != nil {
		return bpmRegistryCredentials{}, false
	}

	var response struct {
		Username string `json:"Username"`
		Secret   string `json:"Secret"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		return bpmRegistryCredentials{}, false
	}
	if response.Username == "" || response.Secret == "" {
		return bpmRegistryCredentials{}, false
	}

	return bpmRegistryCredentials{
		username: response.Username,
		password: response.Secret,
	}, true
}

func dockerCredentialServerURLs(registry string) []string {
	return []string{
		registry,
		"https://" + registry,
		"http://" + registry,
		"https://" + registry + "/v1/",
		"http://" + registry + "/v1/",
		registry + "/v1/",
	}
}
