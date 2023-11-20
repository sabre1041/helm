/*
Copyright The Helm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/gosuri/uitable"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"helm.sh/helm/v3/pkg/cli/output"
	"helm.sh/helm/v3/pkg/registry"
)

const searchRegistryDesc = `
Search reads through all of the repositories configured on the system, and
looks for matches. Search of these repositories uses the metadata stored on
the system.

It will display the latest stable versions of the charts found. If you
specify the --devel flag, the output will include pre-release versions.
If you want to search using a version constraint, use --version.

Examples:

    # Search for stable release versions matching the keyword "nginx"
    $ helm search repo nginx

    # Search for release versions matching the keyword "nginx", including pre-release versions
    $ helm search repo nginx --devel

    # Search for the latest stable release for nginx-ingress with a major version of 1
    $ helm search repo nginx-ingress --version ^1.0.0

Repositories are managed with 'helm repo' commands.
`
const ociPrefix = "oci://"

// searchMaxScore suggests that any score higher than this is not considered a match.
// const searchMaxScore = 25

type searchRegistryOptions struct {
	versions       bool
	regexp         bool
	devel          bool
	version        string
	maxColWidth    uint
	limit          int
	repoFile       string
	repoCacheDir   string
	registryClient *registry.Client
	outputFormat   output.Format
	failOnNoResult bool

	certFile              string
	keyFile               string
	caFile                string
	insecureSkipTLSverify bool
	plainHTTP             bool
}

func newSearchRegistryCmd(out io.Writer) *cobra.Command {
	o := &searchRegistryOptions{}

	cmd := &cobra.Command{
		Use:   "registry [remote]",
		Short: "search registries for charts",
		Long:  searchRepoDesc,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.repoFile = settings.RepositoryConfig
			o.repoCacheDir = settings.RepositoryCache

			registryClient, err := newRegistryClient(o.certFile, o.keyFile, o.caFile, o.insecureSkipTLSverify, o.plainHTTP)
			if err != nil {
				return fmt.Errorf("missing registry client: %w", err)
			}

			o.registryClient = registryClient

			return o.run(out, args)
		},
	}

	f := cmd.Flags()
	f.BoolVarP(&o.regexp, "regexp", "r", false, "use regular expressions for searching repositories you have added")
	f.BoolVarP(&o.versions, "versions", "l", false, "show the long listing, with each version of each chart on its own line, for repositories you have added")
	f.BoolVar(&o.devel, "devel", false, "use development versions (alpha, beta, and release candidate releases), too. Equivalent to version '>0.0.0-0'. If --version is set, this is ignored")
	f.StringVar(&o.version, "version", "", "search using semantic versioning constraints on repositories you have added")
	f.UintVar(&o.maxColWidth, "max-col-width", 50, "maximum column width for output table")
	f.IntVar(&o.limit, "limit", 50, "maximum number of results to return")
	f.BoolVar(&o.failOnNoResult, "fail-on-no-result", false, "search fails if no results are found")

	bindOutputFlag(cmd, &o.outputFormat)

	return cmd
}

func (o *searchRegistryOptions) run(out io.Writer, args []string) error {

	o.setupSearchedVersion()

	q := strings.Join(args, " ")

	if !strings.HasPrefix(q, ociPrefix) {
		return errors.New(fmt.Sprintf("Invalid scheme. Registry scheme must begin with %s", ociPrefix))
	}

	ref := strings.TrimPrefix(q, fmt.Sprintf("%s://", registry.OCIScheme))

	var searchOpts []registry.SearchOption

	searchOpts = append(searchOpts,
		registry.SearchOptVersion(o.version),
		registry.SearchOptVersions(o.versions),
		registry.SearchOptLimit(o.limit))

	searchResults, err := o.registryClient.Search(ref, searchOpts...)
	if err != nil {
		return err
	}

	return o.outputFormat.Write(out, &registrySearchWriter{searchResults.Charts, o.maxColWidth, o.failOnNoResult})
}

func (o *searchRegistryOptions) setupSearchedVersion() {
	debug("Original chart version: %q", o.version)

	if o.version != "" {
		return
	}

	if o.devel { // search for releases and prereleases (alpha, beta, and release candidate releases).
		debug("setting version to >0.0.0-0")
		o.version = ">0.0.0-0"
	} else { // search only for stable releases, prerelease versions will be skip
		debug("setting version to >0.0.0")
		o.version = ">0.0.0"
	}
}

type registryChartElement struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	AppVersion  string `json:"app_version"`
	Description string `json:"description"`
}

type registrySearchWriter struct {
	results        []*registry.SearchResultChart
	columnWidth    uint
	failOnNoResult bool
}

func (r *registrySearchWriter) WriteTable(out io.Writer) error {
	if len(r.results) == 0 {
		// Fail if no results found and --fail-on-no-result is enabled
		if r.failOnNoResult {
			return fmt.Errorf("no results found")
		}

		_, err := out.Write([]byte("No results found\n"))
		if err != nil {
			return fmt.Errorf("unable to write results: %s", err)
		}
		return nil
	}
	table := uitable.New()
	table.MaxColWidth = r.columnWidth
	table.AddRow("REFERENCE", "CHART VERSION", "APP VERSION", "DESCRIPTION")
	for _, r := range r.results {
		table.AddRow(r.Reference, r.Chart.Version, r.Chart.AppVersion, r.Chart.Description)
	}
	return output.EncodeTable(out, table)
}

func (r *registrySearchWriter) WriteJSON(out io.Writer) error {
	return r.encodeByFormat(out, output.JSON)
}

func (r *registrySearchWriter) WriteYAML(out io.Writer) error {
	return r.encodeByFormat(out, output.YAML)
}

func (r *registrySearchWriter) encodeByFormat(out io.Writer, format output.Format) error {
	// Fail if no results found and --fail-on-no-result is enabled
	if len(r.results) == 0 && r.failOnNoResult {
		return fmt.Errorf("no results found")
	}

	// Initialize the array so no results returns an empty array instead of null
	chartList := make([]registryChartElement, 0, len(r.results))

	for _, r := range r.results {
		chartList = append(chartList, registryChartElement{r.Reference, r.Chart.Version, r.Chart.AppVersion, r.Chart.Description})
	}

	switch format {
	case output.JSON:
		return output.EncodeJSON(out, chartList)
	case output.YAML:
		return output.EncodeYAML(out, chartList)
	}

	// Because this is a non-exported function and only called internally by
	// WriteJSON and WriteYAML, we shouldn't get invalid types
	return nil
}
