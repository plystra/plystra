package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/plystra/plystra/internal/templates"
)

func runTemplates(command string, args []string) error {
	switch command {
	case "list":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(templates.Catalog())
	case "describe":
		flags := flag.NewFlagSet("templates describe", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		if err := flags.Parse(args); err != nil {
			return err
		}
		if flags.NArg() != 1 {
			return fmt.Errorf("template_id is required")
		}
		tpl, ok := templates.ByID(flags.Arg(0))
		if !ok {
			return fmt.Errorf("template %q was not found", flags.Arg(0))
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]any{
			"template": tpl,
			"preview":  templates.Preview(tpl, []string{}, []templates.CapabilityRequirement{}, map[string]string{}),
			"install": map[string]any{
				"api":      fmt.Sprintf("POST /api/v1/templates/%s/install", tpl.ID),
				"requires": "admin credential with templates:manage",
			},
		})
	default:
		return fmt.Errorf("unknown templates command %q", command)
	}
}
