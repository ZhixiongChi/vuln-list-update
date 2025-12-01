package elxr

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	trackerDir         = "tracker"
	securityTrackerURL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/archive/master/security-tracker-master.tar.gz//security-tracker-master"
	extendTrackerURL   = "https://gitlab.com/elxr/security-support/elxr-cve-tracker/-/raw/main/data/ESA/list"
	elxrDistroURL      = "https://gitlab.com/elxr/security-support/elxr-cve-tracker/-/raw/main/elxr-distributions.json"
	sourcesURL         = "https://ftp.debian.org/debian/dists/%s/%s/source/Sources.gz"
	extendSourcesURL   = "https://mirror.elxr.dev/elxr/dists/%s/%s/source/Sources.gz"
	securitySourcesURL = "https://security.debian.org/debian-security/dists/%s-security/updates/%s/source/Sources.xz"
)

var (
	repos = []string{
		"main",
		"contrib",
		"non-free",
	}
)

var (
	elxrRepos = []string{
		"main",
		"contrib",
	}
)

type Bug struct {
	Header      *Header
	Annotations []*Annotation
}

type listParser interface {
	ParseHeader(string) *Header
	Dir() string
}

type options struct {
	trackerURL         string
	extendTrackerURL   string
	elxrDistroURL      string
	sourcesURL         string
	extendSourcesURL   string
	securitySourcesURL string
	vulnListDir        string
}

type option func(*options)

func WithTrackerURL(url string) option {
	return func(opts *options) {
		opts.trackerURL = url
	}
}

func WithExtendTrackerURL(url string) option {
	return func(opts *options) {
		opts.extendTrackerURL = url
	}
}

func WithElxrDistroURL(url string) option {
	return func(opts *options) {
		opts.elxrDistroURL = url
	}
}

func WithSourcesURL(url string) option {
	return func(opts *options) {
		opts.sourcesURL = url
	}
}

func WithExtendSourcesURL(url string) option {
	return func(opts *options) {
		opts.extendSourcesURL = url
	}
}

func WithSecuritySourcesURL(url string) option {
	return func(opts *options) {
		opts.securitySourcesURL = url
	}
}

func WithVulnListDir(dir string) option {
	return func(opts *options) {
		opts.vulnListDir = dir
	}
}

type Client struct {
	*options
	parsers       []listParser
	annDispatcher annotationDispatcher
}

func NewClient(opts ...option) Client {
	o := &options{
		trackerURL:         securityTrackerURL,
		extendTrackerURL:   extendTrackerURL,
		elxrDistroURL:      elxrDistroURL,
		sourcesURL:         sourcesURL,
		extendSourcesURL:   extendSourcesURL,
		securitySourcesURL: securitySourcesURL,
		vulnListDir:        utils.VulnListDir(),
	}

	for _, opt := range opts {
		opt(o)
	}

	return Client{
		options: o,
		parsers: []listParser{
			cveList{},
			dlaList{},
			dsaList{},
			esaList{},
		},
		annDispatcher: newAnnotationDispatcher(),
	}
}

func (c Client) Update() error {
	ctx := context.Background()

	log.Println("Removing old Debian data...")
	if err := os.RemoveAll(filepath.Join(c.vulnListDir, trackerDir)); err != nil {
		return xerrors.Errorf("failed to remove Debian dir: %w", err)
	}

	log.Println("Fetching Debian data...")
	tmpDir, err := utils.DownloadToTempDir(ctx, c.trackerURL)
	if err != nil {
		return xerrors.Errorf("failed to retrieve Debian Security Tracker: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	log.Println("Fetching eLxr data...")
	tmpFile, err := utils.DownloadToTempFile(ctx, c.extendTrackerURL)
	if err != nil {
		return xerrors.Errorf("failed to retrieve eLxr Security Tracker: %w", err)
	}
	defer os.RemoveAll(tmpFile)

	dstDir := filepath.Join(tmpDir, "data", "ESA")
	if err := os.MkdirAll(dstDir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir %s: %w", dstDir, err)
	}

	dstPath := filepath.Join(dstDir, "list")
	if err := os.Rename(tmpFile, dstPath); err != nil {
		return xerrors.Errorf("failed to move the extend ESA data from eLxr: %w", err)
	}

	for _, p := range c.parsers {
		list := filepath.Join(tmpDir, "data", p.Dir(), "list")
		bugs, err := c.parseList(p, list)
		if err != nil {
			return xerrors.Errorf("debian parse error: %w", err)
		}

		if err = c.update(p.Dir(), bugs); err != nil {
			return xerrors.Errorf("debian update error: %w", err)
		}
	}

	log.Println("Fetching eLxr distributions...")
	tmpDistroFile, err := utils.DownloadToTempFile(ctx, c.elxrDistroURL)
	if err != nil {
		return xerrors.Errorf("failed to retrieve eLxr Distribution: %w", err)
	}
	defer os.RemoveAll(tmpDistroFile)

	elxrDstPath := filepath.Join(tmpDir, "elxr-distributions.json")
	if err := os.Rename(tmpDistroFile, elxrDstPath); err != nil {
		return xerrors.Errorf("failed to move the elxr distribution: %w", err)
	}

	log.Println("Parsing Debian/eLxr distributions.json...")
	distroSources, err := c.parseDistributions(tmpDir)
	if err != nil {
		return xerrors.Errorf("failed to update distributions: %w", err)
	}

	debDists := distroSources.DebianDists
	distributionJSON := filepath.Join(c.vulnListDir, trackerDir, "distributions.json")
	if err = utils.Write(distributionJSON, debDists); err != nil {
		return xerrors.Errorf("unable to write %s: %w", distributionJSON, err)
	}

	elxrDists := distroSources.ElxrDists
	elxrDistributionJSON := filepath.Join(c.vulnListDir, trackerDir, "elxr-distributions.json")
	if err = utils.Write(elxrDistributionJSON, elxrDists); err != nil {
		return xerrors.Errorf("unable to write %s: %w", elxrDistributionJSON, err)
	}

	err = c.updateSources(ctx, debDists)
	if err != nil {
		return xerrors.Errorf("unable to fetch Debian Sources: %w", err)
	}

	err = c.updateElxrSources(ctx, elxrDists)
	if err != nil {
		return xerrors.Errorf("unable to fetch eLxr Sources: %w", err)
	}

	return nil
}

func (c Client) update(dirname string, bugs []Bug) error {
	// Save all JSON files
	log.Printf("Saving Debian %s data...", dirname)
	if dirname == "ESA" {
		log.Printf("Saving eLxr %s data...", dirname)
	}
	bar := pb.StartNew(len(bugs))
	for _, bug := range bugs {
		dir := filepath.Join(c.vulnListDir, trackerDir, dirname)
		if dirname == "CVE" {
			if strings.HasSuffix(bug.Header.ID, "-XXXX") {
				var bugno int
				for _, ann := range bug.Annotations {
					if ann.Type == "package" && ann.BugNo != 0 {
						bugno = ann.BugNo
						break
					}
				}

				bug.Header.ID = tempBugName(bugno, bug.Header.Description)

				fileName := fmt.Sprintf("%s.json", bug.Header.ID)
				filePath := filepath.Join(dir, "TEMP", fileName)
				if err := utils.Write(filePath, bug); err != nil {
					return xerrors.Errorf("debian: write error (%s): %w", filePath, err)
				}
			} else {
				if err := utils.SaveCVEPerYear(dir, bug.Header.ID, bug); err != nil {
					return xerrors.Errorf("debian: failed to save CVE per year: %w", err)
				}
			}
		} else {
			fileName := fmt.Sprintf("%s.json", bug.Header.ID)
			filePath := filepath.Join(dir, fileName)
			if err := utils.Write(filePath, bug); err != nil {
				return xerrors.Errorf("debian: write error (%s): %w", filePath, err)
			}
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L198
func (c Client) parseList(parser listParser, filename string) ([]Bug, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s: %w", filename, err)
	}

	var (
		bugs   []Bug
		anns   []*Annotation
		header *Header
	)

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()

		switch {
		case line == "":
			continue
		case line[0] == ' ' || line[0] == '\t':
			if header == nil {
				log.Printf("header expected: %s", line)
				continue
			}

			ann := c.annDispatcher.parseAnnotation(line)
			if ann != nil {
				anns = append(anns, ann)
			}
		default:
			if header != nil {
				if shouldStore(anns) {
					bugs = append(bugs, Bug{
						Header:      header,
						Annotations: anns,
					})
				}
				header = nil
				anns = []*Annotation{}
			}
			header = parser.ParseHeader(line)
			if header == nil {
				log.Printf("malformed header: %s", line)
				continue
			}
		}
	}

	if err = s.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	if header != nil && shouldStore(anns) {
		bugs = append(bugs, Bug{
			Header:      header,
			Annotations: anns,
		})
	}

	return bugs, nil
}

type Distribution struct {
	MajorVersion string `json:"major-version"`
	Support      string `json:"support"`
	Contact      string `json:"contact"`
}

type DistroSources struct {
	DebianDists map[string]Distribution
	ElxrDists   map[string]Distribution
}

func (c Client) parseDistributions(dir string) (DistroSources, error) {
	debFile := filepath.Join(dir, "static", "distributions.json")
	f, err := os.Open(debFile)
	if err != nil {
		return DistroSources{}, xerrors.Errorf("unable to open %s: %w", debFile, err)
	}
	defer f.Close()

	// For schema validation
	debDists := map[string]Distribution{}
	if err = json.NewDecoder(f).Decode(&debDists); err != nil {
		return DistroSources{}, xerrors.Errorf("json error: %w", err)
	}

	elxrFile := filepath.Join(dir, "elxr-distributions.json")
	f, err = os.Open(elxrFile)
	if err != nil {
		return DistroSources{}, xerrors.Errorf("unable to open %s: %w", elxrFile, err)
	}
	defer f.Close()

	// For schema validation
	elxrDists := map[string]Distribution{}
	if err = json.NewDecoder(f).Decode(&elxrDists); err != nil {
		return DistroSources{}, xerrors.Errorf("json error: %w", err)
	}

	return DistroSources{
		DebianDists: debDists,
		ElxrDists:   elxrDists,
	}, nil
}

func shouldStore(anns []*Annotation) bool {
	for _, ann := range anns {
		// RESERVED should not have any information as below, but it is not always the case. We don't skip RESERVED here.
		// https://security-team.debian.org/security_tracker.html#reserved-entries
		if ann.Type == "REJECTED" || ann.Type == "NOT-FOR-US" {
			return false
		}
	}
	return true
}

func (c Client) updateElxrSources(ctx context.Context, dists map[string]Distribution) error {
	for target, baseURL := range map[string]string{
		"elxr-source": c.extendSourcesURL,
	} {
		for code := range dists {
			for _, r := range elxrRepos {
				log.Printf("Updating %s %s/%s", target, code, r)
				log.Printf("baseURL %s", baseURL)
				url := fmt.Sprintf(baseURL, code, r)
				headers, err := c.fetchSources(ctx, url)
				if err != nil {
					return xerrors.Errorf("unable to fetch sources: %w", err)
				}

				processedPackages := make(map[string]bool)
				for _, header := range headers {
					name := header.Get("Package")
					if name == "" {
						continue
					}

					if processedPackages[name] {
						continue
					}

					filePath := filepath.Join(c.vulnListDir, trackerDir, target, code, r, name[:1], name+".json")
					if err = utils.Write(filePath, header); err != nil {
						return xerrors.Errorf("source write error: %w", err)
					}
					processedPackages[name] = true
				}
			}
		}
	}
	return nil
}

func (c Client) updateSources(ctx context.Context, dists map[string]Distribution) error {
	for target, baseURL := range map[string]string{
		"source":         c.sourcesURL,
		"updates-source": c.securitySourcesURL,
	} {
		for code := range dists {
			for _, r := range repos {
				log.Printf("Updating %s %s/%s", target, code, r)
				url := fmt.Sprintf(baseURL, code, r)
				headers, err := c.fetchSources(ctx, url)
				if err != nil {
					return xerrors.Errorf("unable to fetch sources: %w", err)
				}

				for _, header := range headers {
					name := header.Get("Package")
					if name == "" {
						continue
					}

					filePath := filepath.Join(c.vulnListDir, trackerDir, target, code, r, name[:1], name+".json")
					if err = utils.Write(filePath, header); err != nil {
						return xerrors.Errorf("source write error: %w", err)
					}
				}
			}
		}
	}
	return nil
}

func (c Client) fetchSources(ctx context.Context, url string) ([]textproto.MIMEHeader, error) {
	tmpFile, err := utils.DownloadToTempFile(ctx, url)
	if err != nil {
		// Some codes don't have Sources in the repository
		if strings.Contains(err.Error(), "bad response code: 404") {
			return nil, nil
		}
		return nil, xerrors.Errorf("sources download error: %w", err)
	}
	defer os.Remove(tmpFile)

	headers, err := c.parseSources(tmpFile)
	if err != nil {
		return nil, xerrors.Errorf("sources parse error: %w", err)
	}

	return headers, nil
}

func (c Client) parseSources(sourcePath string) ([]textproto.MIMEHeader, error) {
	f, err := os.Open(sourcePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	var headers []textproto.MIMEHeader
	buf := new(bytes.Buffer)
	s := bufio.NewScanner(f)
	for s.Scan() {
		// Split into each package
		line := s.Text()
		buf.WriteString(line + "\n")
		if line != "" {
			continue
		}

		// Parse package detail
		r := textproto.NewReader(bufio.NewReader(buf))
		header, err := r.ReadMIMEHeader()
		if err != nil {
			return nil, xerrors.Errorf("MIME header error: %w", err)
		}
		headers = append(headers, header)
		buf.Reset()
	}

	return headers, nil
}

// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/bugs.py#L402
func tempBugName(bugNumber int, description string) string {
	switch {
	case strings.HasPrefix(description, "["):
		description = strings.TrimPrefix(strings.TrimSuffix(description, "]"), "[")
	case strings.HasPrefix(description, "("):
		description = strings.TrimPrefix(strings.TrimSuffix(description, ")"), "(")
	}
	hash := fmt.Sprintf("%x", md5.Sum([]byte(description)))
	return fmt.Sprintf("TEMP-%07d-%s", bugNumber, strings.ToUpper(hash[:6]))
}
