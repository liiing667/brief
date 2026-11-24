// Package remote resolves remote sources (git URLs, registry packages)
// to local directories for scanning.
package remote

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	gitclone "github.com/git-pkgs/clone"
	forges "github.com/git-pkgs/forge"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
)

// Source describes where a remote project came from.
type Source struct {
	Dir     string     // local directory to scan
	Cleanup func()     // call when done (removes temp dir unless --keep)
	Origin  string     // original URL or package identifier
	Kind    SourceKind // local, remote, or registry
	Scheme  string     // lower-case URL scheme for remote sources
}

// SourceKind identifies how a source argument was classified.
type SourceKind string

const (
	SourceKindLocal    SourceKind = "local"
	SourceKindRemote   SourceKind = "remote"
	SourceKindRegistry SourceKind = "registry"
)

// UnsupportedSourceError reports a source that was recognized as a URL but
// cannot be resolved safely. Kind and Scheme retain the rejected source's
// category for callers and error messages.
type UnsupportedSourceError struct {
	Kind   SourceKind
	Scheme string
	Reason string
}

func (e *UnsupportedSourceError) Error() string {
	if e.Scheme == "" {
		return fmt.Sprintf("unsupported %s source: %s", e.Kind, e.Reason)
	}
	return fmt.Sprintf("unsupported %s source scheme %q: %s", e.Kind, e.Scheme, e.Reason)
}

// Options configures remote source resolution.
type Options struct {
	Keep  bool   // don't delete temp dir after scanning
	Depth int    // git clone depth (0 = full clone, -1 or unset = default shallow)
	Dir   string // directory to clone into (empty = temp dir)
	Cache string // persistent shallow clone cache directory (empty = no cache)
}

// Resolve takes a source string and returns a local directory to scan.
// Handles:
//   - Local paths (returned as-is)
//   - Git URLs over https, ssh, or git@ (plain http, git://, and file URIs
//     are rejected before cloning)
//   - Registry shorthands (npm:lodash, gem:rails, pypi:requests, crate:serde)
func Resolve(ctx context.Context, source string, opts Options) (*Source, error) {
	if opts.Depth < 0 {
		opts.Depth = 1
	}

	// Check if it's a registry shorthand
	if ecosystem, name, ok := parseRegistryShorthand(source); ok {
		src, err := resolveRegistryPackage(ctx, ecosystem, name, opts)
		if err != nil {
			return &Source{Origin: source, Kind: SourceKindRegistry}, err
		}
		src.Kind = SourceKindRegistry
		return src, nil
	}

	// Classify the source before it can reach the filesystem. Unknown URL
	// schemes must not fall through to the local-path branch.
	kind, scheme, err := classifySource(source)
	if err != nil {
		return &Source{Origin: source, Kind: kind, Scheme: scheme}, err
	}
	if kind == SourceKindRemote {
		return resolveGitURL(ctx, source, opts)
	}

	// Local path
	return &Source{Dir: source, Cleanup: func() {}, Kind: SourceKindLocal}, nil
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

func classifySource(source string) (SourceKind, string, error) {
	if _, ok := explicitScheme(source); ok || isSCPSource(source) {
		scheme, err := validateRemoteSource(source)
		return SourceKindRemote, scheme, err
	}
	return SourceKindLocal, "", nil
}

// explicitScheme extracts a URL scheme without mistaking Windows drive letters
// or ordinary local names containing a colon for remote sources.
func explicitScheme(source string) (string, bool) {
	i := strings.IndexByte(source, ':')
	if i <= 0 {
		return "", false
	}
	raw := source[:i]
	if len(raw) == 1 && isASCIILetter(raw[0]) {
		return "", false
	}
	for j := 0; j < len(raw); j++ {
		c := raw[j]
		if !isASCIILetter(c) && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
			return "", false
		}
	}
	scheme := strings.ToLower(raw)
	// A known scheme is authoritative even without "//" so file: and http:
	// variants are rejected instead of becoming local paths. Unknown schemes
	// without an authority are left alone to keep local names like "dir:name".
	if !strings.HasPrefix(source[i+1:], "//") && !knownScheme(scheme) {
		return "", false
	}
	return scheme, true
}

func knownScheme(scheme string) bool {
	switch scheme {
	case "file", "git", "git+https", "git+ssh", "http", "https", "ssh":
		return true
	}
	return false
}

func isSCPSource(source string) bool {
	if strings.Contains(source, "://") {
		return false
	}
	at := strings.IndexByte(source, '@')
	if at <= 0 || at == len(source)-1 {
		return false
	}
	rest := source[at+1:]
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 {
		return false
	}
	if slash := strings.IndexByte(rest, '/'); slash >= 0 && slash < colon {
		return false
	}
	return true
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// validateRemoteSource accepts encrypted git transports only. Plain HTTP and
// git:// are rejected before any clone or filesystem access.
func validateRemoteSource(source string) (string, error) {
	scheme, ok := explicitScheme(source)
	if !ok {
		if isSCPSource(source) {
			return "ssh", nil
		}
		return "", &UnsupportedSourceError{
			Kind:   SourceKindRemote,
			Reason: "expected an https, ssh, or git@ remote URL",
		}
	}
	switch scheme {
	case "https", "ssh":
		return scheme, nil
	case "http", "git":
		return scheme, &UnsupportedSourceError{
			Kind:   SourceKindRemote,
			Scheme: scheme,
			Reason: "insecure plaintext transport; use https or ssh",
		}
	case "file":
		return scheme, &UnsupportedSourceError{
			Kind:   SourceKindRemote,
			Scheme: scheme,
			Reason: "file URIs are not local directories; pass the directory path directly",
		}
	default:
		return scheme, &UnsupportedSourceError{
			Kind:   SourceKindRemote,
			Scheme: scheme,
			Reason: "only https, ssh, and git@ URLs are supported",
		}
	}
}

// resolveGitURL clones a git URL to a temp directory.
// Preserves the original URL for cloning (SSH, HTTPS, etc.) to respect
// the user's auth configuration.
func resolveGitURL(ctx context.Context, url string, opts Options) (*Source, error) {
	scheme, err := validateRemoteSource(url)
	if err != nil {
		return &Source{Origin: url, Kind: SourceKindRemote, Scheme: scheme}, err
	}
	// Parse to extract the repo name for the temp dir, but clone with the
	// original URL to preserve transport (SSH vs HTTPS) and credentials.
	_, _, repo, parseErr := forges.ParseRepoURL(url)
	if parseErr != nil {
		repo = ""
	}

	src, err := cloneURL(ctx, url, repo, opts)
	if err != nil {
		return &Source{Origin: url, Kind: SourceKindRemote, Scheme: scheme}, err
	}
	src.Kind = SourceKindRemote
	src.Scheme = scheme

	return src, nil
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

	return resolveGitURL(ctx, pkg.Repository, opts)
}

func cloneURL(ctx context.Context, url, name string, opts Options) (*Source, error) {
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
	if _, err := validateRemoteSource(url); err != nil {
		return err
	}
	if !strings.HasPrefix(url, "https://") {
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
