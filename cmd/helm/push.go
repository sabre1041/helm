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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"helm.sh/helm/v3/cmd/helm/require"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli/output"
	"helm.sh/helm/v3/pkg/pusher"
	"helm.sh/helm/v3/pkg/registry"
)

const pushDesc = `
Upload a chart to a registry.

If the chart has an associated provenance file,
it will also be uploaded.
`

type pushPrinter struct {
	Registry string   `json:"registry,omitempty"`
	Digest   string   `json:"digest,omitempty"`
	Comments []string `json:"comments,omitempty"`
}

func (p pushPrinter) WriteJSON(out io.Writer) error {
	return output.EncodeJSON(out, p)
}

func (p pushPrinter) WriteYAML(out io.Writer) error {
	return output.EncodeYAML(out, p)
}

func (s pushPrinter) WriteTable(out io.Writer) error {

	fmt.Fprintf(out, "Pushed: %s\n", s.Registry)
	fmt.Fprintf(out, "Digest: %s\n", s.Digest)

	for _, c := range s.Comments {
		fmt.Fprintf(out, "%s\n", c)
	}

	return nil

}

func newPushCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	client := action.NewPushWithOpts(action.WithPushConfig(cfg))
	var outfmt output.Format

	cmd := &cobra.Command{
		Use:   "push [chart] [remote]",
		Short: "push a chart to remote",
		Long:  pushDesc,
		Args:  require.MinimumNArgs(2),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				// Do file completion for the chart file to push
				return nil, cobra.ShellCompDirectiveDefault
			}
			if len(args) == 1 {
				providers := []pusher.Provider(pusher.All(settings))
				var comps []string
				for _, p := range providers {
					for _, scheme := range p.Schemes {
						comps = append(comps, fmt.Sprintf("%s://", scheme))
					}
				}
				return comps, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			chartRef := args[0]
			remote := args[1]
			client.Settings = settings

			// Capture the output
			buf := new(bytes.Buffer)
			registry.ClientOptWriter(buf)(cfg.RegistryClient)

			_, err := client.Run(chartRef, remote)

			if err != nil {
				return err
			}

			pushPrinter := pushPrinter{
				Comments: []string{},
			}

			scanner := bufio.NewScanner(buf)
			for scanner.Scan() {
				line := scanner.Text()
				components := strings.SplitN(line, ":", 2)

				if len(components) == 1 {
					pushPrinter.Comments = append(pushPrinter.Comments, line)
				} else {
					switch components[0] {
					case "Pushed":
						pushPrinter.Registry = strings.TrimSpace(components[1])
					case "Digest":
						pushPrinter.Digest = strings.TrimSpace(components[1])
					default:
						pushPrinter.Comments = append(pushPrinter.Comments, strings.TrimSpace(components[1]))
					}
				}
			}

			return outfmt.Write(out, pushPrinter)
		},
	}

	bindOutputFlag(cmd, &outfmt)

	return cmd
}
