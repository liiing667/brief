// Package remote resolves remote sources (git URLs, registry packages)
// to local directories for scanning.
package remote

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	gitclone "github.com/git-pkgs/clone"
	forges "github.com/git-pkgs/forge"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
)

// Source describes where a remote project came from.
type Source struct {
	Dir     string // local directory to scan
	Cleanup func() // call when done (removes temp dir unless --keep)
	Origin  string // original URL or package identifier
}

// Options configures remote source resolution.
type Options struct {
	Keep  bool   // don't delete temp dir after scanning
	Depth int    // git clone depth (0 = full clone, -1 or unset = default shallow)
	Dir   string // directory to clone into (empty = temp dir)
	Cache string // persistent shallow clone cache directory (empty = no cache)
}

// ErrInsecureRemoteTransport indicates that a remote source uses a
// clear-text transport. It is returned before Git or any registry HTTP
// client opens a connection.
var ErrInsecureRemoteTransport = errors.New("insecure remote transport")

// InsecureRemoteTransportError identifies the rejected source. Source and
// Origin contain a credential-redacted URL so the rejection remains
// auditable without leaking secrets into logs.
type InsecureRemoteTransportError struct {
	Source string
	Origin string
	URL    string
}

func (e *InsecureRemoteTransportError) Error() string {
	transport := "clear-text"
	if e.Source != "" {
		if scheme := remoteScheme(e.Source); scheme != "" {
			transport = strings.ToUpper(scheme)
		}
	}
	return fmt.Sprintf(
		"refusing insecure remote source URL %q before connection; %s is a clear-text transport and may expose credentials; use HTTPS or SSH (%v)",
		e.Source,
		transport,
		ErrInsecureRemoteTransport,
	)
}

func (e *InsecureRemoteTransportError) Unwrap() error {
	return ErrInsecureRemoteTransport
}

// Compatibility aliases for callers and tests that name the rejection more
// specifically.
var (
	ErrInsecureRemote    = ErrInsecureRemoteTransport
	ErrInsecureTransport = ErrInsecureRemoteTransport
	ErrInsecureURL       = ErrInsecureRemoteTransport
	ErrInsecureHTTP      = ErrInsecureRemoteTransport
)

type (
	InsecureRemoteError    = InsecureRemoteTransportError
	InsecureTransportError = InsecureRemoteTransportError
	InsecureURLError       = InsecureRemoteTransportError
	InsecureHTTPError      = InsecureRemoteTransportError
	InsecureGitURLError    = InsecureRemoteTransportError
)

// Resolve takes a source string and returns a local directory to scan.
// Handles:
//   - Local paths (returned as-is)
//   - Git URLs (https://github.com/owner/repo)
//   - Registry shorthands (npm:lodash, gem:rails, pypi:requests, crate:serde)
func Resolve(ctx context.Context, source string, opts Options) (*Source, error) {
	if opts.Depth < 0 {
		opts.Depth = 1
	}

	// Check if it's a registry shorthand
	if ecosystem, name, ok := parseRegistryShorthand(source); ok {
		return resolveRegistryPackage(ctx, ecosystem, name, opts)
	}

	// Check if it's a URL
	if isURL(source) {
		return resolveGitURL(ctx, source, opts)
	}

	// Local path
	return &Source{Dir: source, Cleanup: func() {}}, nil
}

// parseRegistryShorthand checks if the source looks like "npm:lodash" or "gem:rails".
func parseRegistryShorthand(source string) (ecosystem, name string, ok bool) {
	const splitParts = 2
	parts := strings.SplitN(source, ":", splitParts)
	if len(parts) != splitParts {
		return "", "", false
	}
	prefix := parts[0]
	// Map shorthand prefixes to purl ecosystems
	ecosystems := map[string]string{
		"npm":   "npm",
		"gem":   "gem",
		"pypi":  "pypi",
		"crate": "cargo",
		"go":    "golang",
		"hex":   "hex",
		"nuget": "nuget",
		"pub":   "pub",
	}
	eco, ok := ecosystems[prefix]
	if !ok {
		return "", "", false
	}
	return eco, parts[1], true
}

func isURL(s string) bool {
	trimmed := strings.TrimSpace(s)
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(trimmed, "git@") ||
		strings.HasPrefix(lower, "ssh://")
}

var userinfoPattern = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*://)[^/\s]*@`)

// redactRemoteOrigin removes userinfo while retaining the scheme, host, and
// path for audit records.
func redactRemoteOrigin(raw string) string {
	return userinfoPattern.ReplaceAllString(strings.TrimSpace(raw), "${1}REDACTED@")
}

func remoteScheme(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		return strings.ToLower(raw[:i])
	}
	return ""
}

// insecureRemoteTransport reports schemes that can disclose repository
// contents or credentials to a network observer.
func insecureRemoteTransport(raw string) bool {
	return remoteScheme(raw) == "http"
}

func ensureSecureRemoteTransport(raw string) error {
	if !insecureRemoteTransport(raw) {
		return nil
	}

	origin := redactRemoteOrigin(raw)
	return &InsecureRemoteTransportError{
		Source: origin,
		Origin: origin,
		URL:    origin,
	}
}

// RejectInsecureRemote is an exported audit hook for pipelines that resolve
// sources outside Resolve but want the same pre-connection policy.
func RejectInsecureRemote(raw string) error {
	return ensureSecureRemoteTransport(raw)
}

// resolveGitURL clones a git URL to a temp directory.
// Preserves the original URL for cloning (SSH, HTTPS, etc.) to respect
// the user's auth configuration.
func resolveGitURL(ctx context.Context, url string, opts Options) (*Source, error) {
	url = strings.TrimSpace(url)
	if err := ensureSecureRemoteTransport(url); err != nil {
		return nil, err
	}

	// Parse to extract the repo name for the temp dir, but clone with the
	// original URL to preserve transport (SSH vs HTTPS) and credentials.
	_, _, repo, err := forges.ParseRepoURL(url)
	if err != nil {
		return cloneURL(ctx, url, "", opts)
	}

	return cloneURL(ctx, url, repo, opts)
}

// resolveRegistryPackage looks up a package in its registry to find the source repo.
func resolveRegistryPackage(ctx context.Context, ecosystem, name string, opts Options) (*Source, error) {
	purlStr := purl.MakePURLString(ecosystem, name, "")
	client := registries.DefaultClient()
	pkg, err := registries.FetchPackageFromPURL(ctx, purlStr, client)
	if err != nil {
		return nil, fmt.Errorf("looking up %s:%s: %w", ecosystem, name, err)
	}

	if pkg.Repository == "" {
		return nil, fmt.Errorf("%s:%s has no source repository", ecosystem, name)
	}

	source, err := resolveGitURL(ctx, pkg.Repository, opts)
	if err != nil {
		return nil, fmt.Errorf("resolving source for %s:%s: %w", ecosystem, name, err)
	}
	return source, nil
}

func cloneURL(ctx context.Context, url, name string, opts Options) (*Source, error) {
	if err := ensureSecureRemoteTransport(url); err != nil {
		return nil, err
	}

	var dir string
	var managed bool

	if opts.Dir != "" {
		dir = opts.Dir
	} else {
		if name == "" {
			name = "brief-remote"
		}
		tmp, err := os.MkdirTemp("", "brief-"+name+"-*")
		if err != nil {
			return nil, fmt.Errorf("creating temp dir: %w", err)
		}
		dir = tmp
		managed = true
	}

	if err := cloneInto(ctx, url, dir, opts); err != nil {
		if managed {
			_ = os.RemoveAll(dir)
		}
		return nil, err
	}

	cleanup := func() {
		if managed && !opts.Keep {
			_ = os.RemoveAll(dir)
		}
	}

	return &Source{Dir: dir, Cleanup: cleanup, Origin: url}, nil
}

var ensureClone = func(ctx context.Context, url, dst string, full bool) error {
	return gitclone.Ensure(ctx, gitclone.Retry{}, url, dst, "", full)
}

var prepareCloneCache = func(ctx context.Context, root, url, dst string) error {
	cache := gitclone.Cache{Root: root}
	_, err := cache.Prepare(ctx, url, "", dst)
	return err
}

var execClone = func(ctx context.Context, url, dir string, depth int) error {
	if err := ensureSecureRemoteTransport(url); err != nil {
		return err
	}

	args := []string{"clone"}
	if depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
	}
	args = append(args, url, dir)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Git already wrote a credential-redacted failure to stderr, so do
		// not repeat the raw URL here.
		return fmt.Errorf("git clone failed: %w", err)
	}
	return nil
}

func cloneInto(ctx context.Context, url, dir string, opts Options) error {
	if err := ensureSecureRemoteTransport(url); err != nil {
		return err
	}

	if remoteScheme(url) != "https" {
		return execClone(ctx, url, dir, opts.Depth)
	}
	if opts.Cache != "" {
		if opts.Dir != "" {
			return errors.New("clone cache cannot be combined with an explicit clone directory")
		}
		if opts.Depth == 0 {
			return errors.New("clone cache does not support full clones (depth 0)")
		}
		if err := prepareCloneCache(ctx, opts.Cache, url, dir); err != nil {
			return fmt.Errorf("preparing clone cache: %w", err)
		}
		return nil
	}
	if err := ensureClone(ctx, url, dir, opts.Depth == 0); err != nil {
		return fmt.Errorf("cloning remote: %w", err)
	}
	return nil
}
