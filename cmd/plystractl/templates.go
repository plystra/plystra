package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/plystra/core/internal/templates"
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
	case "create":
		flags := flag.NewFlagSet("templates create", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		templateID := flags.String("template", "", "template id")
		out := flags.String("out", "", "application output directory")
		appName := flags.String("name", "", "application name")
		if err := flags.Parse(args); err != nil {
			return err
		}
		if strings.TrimSpace(*templateID) == "" && flags.NArg() > 0 {
			*templateID = flags.Arg(0)
		}
		if strings.TrimSpace(*templateID) == "" {
			return fmt.Errorf("--template is required")
		}
		tpl, ok := templates.ByID(strings.TrimSpace(*templateID))
		if !ok {
			return fmt.Errorf("template %q was not found", strings.TrimSpace(*templateID))
		}
		target := strings.TrimSpace(*out)
		if target == "" {
			target = safeOutputDirName(firstNonEmptyString(*appName, tpl.ID))
		}
		result, err := createTemplateApp(tpl, templateCreateOptions{OutputDir: target, AppName: *appName})
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	default:
		return fmt.Errorf("unknown templates command %q", command)
	}
}

type templateCreateOptions struct {
	OutputDir string
	AppName   string
}

func createTemplateApp(tpl templates.Manifest, opts templateCreateOptions) (map[string]any, error) {
	target := filepath.Clean(strings.TrimSpace(opts.OutputDir))
	if target == "." || target == string(filepath.Separator) || target == "" {
		return nil, fmt.Errorf("output directory must be a new non-root directory")
	}
	if _, err := os.Stat(target); err == nil {
		return nil, fmt.Errorf("output directory %q already exists", target)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(target, "plystra"), 0o755); err != nil {
		return nil, err
	}
	appName := strings.TrimSpace(opts.AppName)
	if appName == "" {
		appName = tpl.Name
	}
	preview := templates.Preview(tpl, []string{}, []templates.CapabilityRequirement{}, map[string]string{})
	files := map[string][]byte{}
	manifest := map[string]any{
		"format":              "plystra.template.app.v1",
		"app_name":            appName,
		"template":            tpl,
		"preview":             preview,
		"deployment_profile":  tpl.DeploymentProfile,
		"required_plugins":    tpl.RequiredPlugins,
		"required_capability": tpl.RequiredCapabilities,
	}
	rawManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	files["plystra/template-installation.json"] = append(rawManifest, '\n')
	files["plystra/install-explanation.md"] = []byte(renderInstallExplanation(appName, tpl))
	files["README.md"] = []byte(renderTemplateREADME(appName, tpl))
	files[".env.example"] = []byte(renderTemplateEnv(appName, tpl))
	files["docker-compose.yml"] = []byte(renderTemplateCompose(tpl))
	for name, data := range files {
		path := filepath.Join(target, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		mode := os.FileMode(0o644)
		if name == ".env.example" {
			mode = 0o600
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			return nil, err
		}
	}
	return map[string]any{
		"created":     true,
		"template_id": tpl.ID,
		"app_name":    appName,
		"output_dir":  target,
		"files": []string{
			"README.md",
			".env.example",
			"docker-compose.yml",
			"plystra/template-installation.json",
			"plystra/install-explanation.md",
		},
		"next_steps": []string{
			"review plystra/install-explanation.md",
			"copy .env.example to .env and set strong secrets",
			"run docker compose --env-file .env up -d postgres",
			"run docker compose --env-file .env run --rm plystra-core plystractl migrate up",
			"run docker compose --env-file .env run --rm plystra-core plystractl migrate verify",
			"run docker compose --env-file .env up -d",
		},
	}, nil
}

func renderInstallExplanation(appName string, tpl templates.Manifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Install Explanation: %s\n\n", appName)
	fmt.Fprintf(&b, "Template `%s` generates an inspectable Backend OS Alpha deployment scaffold. Review every file before starting services.\n\n", tpl.ID)
	fmt.Fprintf(&b, "## What This Template Declares\n\n")
	fmt.Fprintf(&b, "- Template: `%s` %s\n", tpl.ID, tpl.Version)
	fmt.Fprintf(&b, "- Required Core: `%s`\n", tpl.RequiresCore)
	fmt.Fprintf(&b, "- Required plugins: %s\n", joinOrNone(tpl.RequiredPlugins))
	fmt.Fprintf(&b, "- Required capabilities: %s\n", capabilitySummary(tpl.RequiredCapabilities))
	fmt.Fprintf(&b, "- Deployment profile: `%s`\n\n", tpl.DeploymentProfile.ID)
	fmt.Fprintf(&b, "## Generated Defaults\n\n")
	writeTemplateList(&b, "Spaces", spaceNames(tpl.Spaces))
	writeTemplateList(&b, "Groups", groupNames(tpl.Groups))
	writeTemplateList(&b, "Roles", roleNames(tpl.Roles))
	writeTemplateList(&b, "Permissions", permissionNames(tpl.Permissions))
	fmt.Fprintf(&b, "## Required Operator Actions\n\n")
	for _, step := range templates.InstallExplanation(tpl, []string{}, []templates.CapabilityRequirement{}, map[string]string{}) {
		fmt.Fprintf(&b, "- %s\n", step)
	}
	fmt.Fprintf(&b, "\n## Limitations\n\n")
	writeTemplateList(&b, "Template limitations", tpl.Limitations)
	return b.String()
}

func renderTemplateREADME(appName string, tpl templates.Manifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", appName)
	fmt.Fprintf(&b, "Generated from Plystra template `%s`.\n\n", tpl.ID)
	b.WriteString("This is a Backend OS Alpha scaffold. It is intentionally transparent: the generated files show required plugins, capability requirements, deployment profile, migration flow, backup flow, and restore flow.\n\n")
	b.WriteString("## Start\n\n")
	b.WriteString("```powershell\n")
	b.WriteString("copy .env.example .env\n")
	b.WriteString("docker compose --env-file .env up -d postgres\n")
	b.WriteString("docker compose --env-file .env run --rm plystra-core plystractl migrate up\n")
	b.WriteString("docker compose --env-file .env run --rm plystra-core plystractl migrate verify\n")
	b.WriteString("docker compose --env-file .env run --rm plystra-core plystractl doctor\n")
	b.WriteString("docker compose --env-file .env up -d\n")
	b.WriteString("```\n\n")
	b.WriteString("## Operate\n\n")
	b.WriteString("- Core health: `GET http://localhost:8080/api/v1/health`\n")
	b.WriteString("- Core readiness: `GET http://localhost:8080/api/v1/ready`\n")
	b.WriteString("- Backup manifest: `docker compose --env-file .env run --rm plystra-core plystractl backup manifest`\n")
	b.WriteString("- Upgrade plan: `docker compose --env-file .env run --rm plystra-core plystractl upgrade plan`\n\n")
	b.WriteString("First-super-admin access is never created by migrations. Use `plystractl admin bootstrap-super-admin` only after creating or selecting the intended User.\n")
	return b.String()
}

func renderTemplateEnv(appName string, tpl templates.Manifest) string {
	_ = appName
	lines := []string{
		"SERVER_HOST=0.0.0.0",
		"SERVER_PORT=8080",
		"SERVER_MODE=production",
		"SERVER_PUBLIC_URL=https://plystra.example.com",
		"POSTGRES_DB=plystra",
		"POSTGRES_USER=plystra",
		"POSTGRES_PASSWORD=replace-with-strong-postgres-password",
		"POSTGRES_PORT=5432",
		"DATABASE_URL=postgres://plystra:replace-with-strong-postgres-password@localhost:5432/plystra?sslmode=require",
		"DOCKER_DATABASE_URL=postgres://plystra:replace-with-strong-postgres-password@postgres:5432/plystra?sslmode=disable",
		"LOG_FORMAT=json",
		"AUDIT_WRITE_MODE=always",
		"TRACE_VERSION=1.0",
		"PLYSTRA_CORE_IMAGE=plystra-core:local",
		"CORS_ALLOWED_ORIGINS=https://app.example.com",
		"TRUSTED_PROXIES=",
		"PLYSTRA_SESSION_SECRET=replace-me",
		"PLYSTRA_API_KEY_SECRET=replace-me-too",
		"PLYSTRA_AUTH_REGISTRATION_ENABLED=false",
		"PLYSTRA_AUTH_REGISTRATION_TOKEN=",
		"PLYSTRA_BOOTSTRAP_REGISTRATION_ENABLED=false",
		"PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN=",
		"PLYSTRA_AUTH_PUBLIC_USER_REGISTRATION_ENABLED=false",
		"DATA_CONSOLE_ENABLED=false",
		"METRICS_ENABLED=false",
		"METRICS_TOKEN=",
	}
	if containsString(tpl.RequiredPlugins, "plystra.auth_complete") {
		lines = append(lines,
			"",
			"# Complete Auth plugin process secrets.",
			"PLYSTRA_AUTH_COMPLETE_IMAGE=plystra-auth-complete:local",
			"AUTH_PLUGIN_PORT=8790",
			"AUTH_PLUGIN_LISTEN_ADDR=0.0.0.0:8790",
			"PLYSTRA_EMAIL_CAPABILITY_TOKEN=replace-me",
		)
	}
	return strings.Join(lines, "\n") + "\n"
}

func renderTemplateCompose(tpl templates.Manifest) string {
	var b strings.Builder
	b.WriteString("services:\n")
	b.WriteString("  plystra-core:\n")
	b.WriteString("    image: ${PLYSTRA_CORE_IMAGE}\n")
	b.WriteString("    environment:\n")
	for _, key := range []string{
		"SERVER_HOST", "SERVER_PORT", "SERVER_MODE", "SERVER_PUBLIC_URL",
		"LOG_FORMAT", "AUDIT_WRITE_MODE", "TRACE_VERSION", "CORS_ALLOWED_ORIGINS",
		"TRUSTED_PROXIES", "PLYSTRA_SESSION_SECRET", "PLYSTRA_API_KEY_SECRET",
		"PLYSTRA_AUTH_REGISTRATION_ENABLED", "PLYSTRA_AUTH_REGISTRATION_TOKEN",
		"PLYSTRA_BOOTSTRAP_REGISTRATION_ENABLED", "PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN",
		"PLYSTRA_AUTH_PUBLIC_USER_REGISTRATION_ENABLED", "DATA_CONSOLE_ENABLED",
		"METRICS_ENABLED", "METRICS_TOKEN",
	} {
		fmt.Fprintf(&b, "      %s: ${%s}\n", key, key)
	}
	b.WriteString("      DATABASE_URL: ${DOCKER_DATABASE_URL}\n")
	b.WriteString("    ports:\n      - \"${SERVER_PORT:-8080}:8080\"\n")
	b.WriteString("    depends_on:\n      postgres:\n        condition: service_healthy\n")
	b.WriteString("    healthcheck:\n      test: [\"CMD-SHELL\", \"wget -qO- http://127.0.0.1:8080/api/v1/health >/dev/null || exit 1\"]\n      interval: 10s\n      timeout: 3s\n      retries: 6\n")
	if containsString(tpl.RequiredPlugins, "plystra.auth_complete") {
		b.WriteString("  auth-complete:\n")
		b.WriteString("    image: ${PLYSTRA_AUTH_COMPLETE_IMAGE}\n")
		b.WriteString("    environment:\n")
		b.WriteString("      AUTH_PLUGIN_LISTEN_ADDR: ${AUTH_PLUGIN_LISTEN_ADDR:-0.0.0.0:8790}\n")
		b.WriteString("      DATABASE_URL: ${DOCKER_DATABASE_URL}\n")
		b.WriteString("      SERVER_MODE: ${SERVER_MODE}\n")
		b.WriteString("      PLYSTRA_SESSION_SECRET: ${PLYSTRA_SESSION_SECRET}\n")
		b.WriteString("      PLYSTRA_EMAIL_CAPABILITY_TOKEN: ${PLYSTRA_EMAIL_CAPABILITY_TOKEN}\n")
		b.WriteString("    ports:\n      - \"${AUTH_PLUGIN_PORT:-8790}:8790\"\n")
		b.WriteString("    depends_on:\n      postgres:\n        condition: service_healthy\n")
		b.WriteString("    healthcheck:\n      test: [\"CMD-SHELL\", \"wget -qO- http://127.0.0.1:8790/health >/dev/null || exit 1\"]\n      interval: 10s\n      timeout: 3s\n      retries: 6\n")
	}
	b.WriteString("  postgres:\n")
	b.WriteString("    image: postgres:16-alpine\n")
	b.WriteString("    environment:\n")
	b.WriteString("      POSTGRES_DB: ${POSTGRES_DB}\n      POSTGRES_USER: ${POSTGRES_USER}\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n")
	b.WriteString("    volumes:\n      - plystra-postgres-data:/var/lib/postgresql/data\n")
	b.WriteString("    healthcheck:\n      test: [\"CMD-SHELL\", \"pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}\"]\n      interval: 5s\n      timeout: 5s\n      retries: 10\n")
	b.WriteString("volumes:\n  plystra-postgres-data:\n")
	return b.String()
}

func writeTemplateList(b *strings.Builder, label string, values []string) {
	fmt.Fprintf(b, "### %s\n\n", label)
	if len(values) == 0 {
		b.WriteString("- none\n\n")
		return
	}
	for _, value := range values {
		fmt.Fprintf(b, "- %s\n", value)
	}
	b.WriteByte('\n')
}

func spaceNames(values []templates.Space) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.Key+" - "+value.Name)
	}
	return out
}

func groupNames(values []templates.Group) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.Key+" - "+value.Name)
	}
	return out
}

func roleNames(values []templates.Role) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.Key)
	}
	return out
}

func permissionNames(values []templates.Permission) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, fmt.Sprintf("%s: %s.%s.%s", value.Role, value.Resource, value.Action, value.Scope))
	}
	return out
}

func capabilitySummary(values []templates.CapabilityRequirement) string {
	if len(values) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, value.ID)
	}
	return strings.Join(parts, ", ")
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func safeOutputDirName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "plystra-app"
	}
	return out
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
