package capability

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

var semverPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

func ParseManifest(data []byte) (Manifest, error) {
	var manifest Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, ValidateManifest(manifest)
}

func ParseConfig(data []byte) (Config, error) {
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}
	seen := map[string]struct{}{}
	for i, item := range config.SystemCapabilities {
		if strings.TrimSpace(item.ID) == "" {
			return Config{}, fmt.Errorf("system_capabilities[%d].id is required", i)
		}
		if _, ok := seen[item.ID]; ok {
			return Config{}, fmt.Errorf("duplicate capability %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		if item.Source == "" {
			item.Source = SourceLocal
		}
		if item.Source != SourceLocal {
			return Config{}, fmt.Errorf("system_capabilities[%d].source must be local in v0", i)
		}
		if strings.TrimSpace(item.Binary) == "" || strings.TrimSpace(item.Manifest) == "" {
			return Config{}, fmt.Errorf("system_capabilities[%d].binary and manifest are required", i)
		}
		config.SystemCapabilities[i] = item
	}
	return config, nil
}

func ParseLockfile(data []byte) (Lockfile, error) {
	var lock Lockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return Lockfile{}, err
	}
	seen := map[string]struct{}{}
	for i, item := range lock.SystemCapabilities {
		if item.ID == "" || item.Version == "" || item.Path == "" || item.Checksum == "" {
			return Lockfile{}, fmt.Errorf("system_capabilities[%d] requires id, version, path, and checksum", i)
		}
		if _, ok := seen[item.ID]; ok {
			return Lockfile{}, fmt.Errorf("duplicate locked capability %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		if item.Source == "" {
			item.Source = SourceLocal
		}
		if item.Source != SourceLocal {
			return Lockfile{}, fmt.Errorf("system_capabilities[%d].source must be local in v0", i)
		}
		lock.SystemCapabilities[i] = item
	}
	return lock, nil
}

func ValidateManifest(manifest Manifest) error {
	if strings.TrimSpace(manifest.ID) == "" {
		return errors.New("id is required")
	}
	if !slices.Contains(RequiredSystemCapabilityOrder, manifest.ID) {
		return fmt.Errorf("unsupported system capability id %q", manifest.ID)
	}
	if manifest.Kind != KindSystemCapability {
		return fmt.Errorf("kind must be %q", KindSystemCapability)
	}
	if strings.TrimSpace(manifest.Name) == "" {
		return errors.New("name is required")
	}
	if !semverPattern.MatchString(manifest.Version) {
		return errors.New("version must be semantic version-like")
	}
	if manifest.Runtime.Type != RuntimeBuiltin && manifest.Runtime.Type != RuntimeProcess {
		return fmt.Errorf("runtime.type must be %q or %q", RuntimeBuiltin, RuntimeProcess)
	}
	if manifest.Runtime.Protocol != ProtocolInProcess && manifest.Runtime.Protocol != ProtocolHTTP && manifest.Runtime.Protocol != ProtocolGRPC {
		return fmt.Errorf("runtime.protocol must be %q, %q, or %q", ProtocolInProcess, ProtocolHTTP, ProtocolGRPC)
	}
	if manifest.Runtime.Type == RuntimeBuiltin && manifest.Runtime.Protocol != ProtocolInProcess {
		return fmt.Errorf("runtime.protocol must be %q for built-in capabilities", ProtocolInProcess)
	}
	if manifest.Runtime.Type == RuntimeProcess && manifest.Runtime.Protocol == ProtocolInProcess {
		return fmt.Errorf("runtime.protocol %q is only valid for built-in capabilities", ProtocolInProcess)
	}
	if manifest.Runtime.Protocol == ProtocolHTTP && strings.TrimSpace(manifest.Runtime.Address) == "" {
		return errors.New("runtime.address is required for http process capabilities")
	}
	if strings.TrimSpace(manifest.Requires.Kernel) == "" {
		return errors.New("requires.kernel is required")
	}
	for _, required := range manifest.Requires.Capabilities {
		if !slices.Contains(RequiredSystemCapabilityOrder, required) {
			return fmt.Errorf("requires.capabilities contains unsupported capability %q", required)
		}
		if required == manifest.ID {
			return fmt.Errorf("capability %q cannot require itself", manifest.ID)
		}
	}
	if len(manifest.Provides.Services) == 0 {
		return errors.New("provides.services is required")
	}
	services := map[string]struct{}{}
	for i, service := range manifest.Provides.Services {
		if strings.TrimSpace(service.Name) == "" {
			return fmt.Errorf("provides.services[%d].name is required", i)
		}
		if reservedBusinessPluginService(service.Name) {
			return fmt.Errorf("service %q is reserved for trusted system capabilities", service.Name)
		}
		services[service.Name] = struct{}{}
	}
	for i, route := range manifest.Provides.Routes {
		if route.Method == "" || route.Path == "" || route.Service == "" || route.Operation == "" {
			return fmt.Errorf("provides.routes[%d] requires method, path, service, and operation", i)
		}
		if _, ok := services[route.Service]; !ok {
			return fmt.Errorf("provides.routes[%d] references unknown service %q", i, route.Service)
		}
		if route.Path[0] != '/' {
			return fmt.Errorf("provides.routes[%d].path must start with /", i)
		}
		if !validMethod(route.Method) {
			return fmt.Errorf("provides.routes[%d].method %q is not supported", i, route.Method)
		}
	}
	if manifest.Provides.Migrations.Namespace == "" || manifest.Provides.Migrations.Path == "" {
		return errors.New("provides.migrations.namespace and path are required")
	}
	if !validMigrationNamespace(manifest.ID, manifest.Provides.Migrations.Namespace) {
		return fmt.Errorf("capability %q cannot own migration namespace %q", manifest.ID, manifest.Provides.Migrations.Namespace)
	}
	if !manifest.Privileged || !manifest.Required {
		return errors.New("official system capabilities must be privileged and required")
	}
	if manifest.Stability == "" {
		return errors.New("stability is required")
	}
	return nil
}

func ResolveOrder(manifests []Manifest) ([]Manifest, error) {
	byID := map[string]Manifest{}
	for _, manifest := range manifests {
		if _, ok := byID[manifest.ID]; ok {
			return nil, fmt.Errorf("duplicate capability %q", manifest.ID)
		}
		byID[manifest.ID] = manifest
	}
	for _, id := range RequiredSystemCapabilityOrder {
		if _, ok := byID[id]; !ok {
			return nil, fmt.Errorf("required capability %q is missing", id)
		}
	}
	var ordered []Manifest
	added := map[string]struct{}{}
	var visit func(string) error
	visiting := map[string]struct{}{}
	visit = func(id string) error {
		if _, ok := added[id]; ok {
			return nil
		}
		if _, ok := visiting[id]; ok {
			return fmt.Errorf("cyclic capability dependency at %q", id)
		}
		manifest, ok := byID[id]
		if !ok {
			return fmt.Errorf("required capability %q is missing", id)
		}
		visiting[id] = struct{}{}
		for _, dep := range manifest.Requires.Capabilities {
			if err := visit(dep); err != nil {
				return err
			}
		}
		delete(visiting, id)
		added[id] = struct{}{}
		ordered = append(ordered, manifest)
		return nil
	}
	for _, id := range RequiredSystemCapabilityOrder {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

func validMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func validMigrationNamespace(id, namespace string) bool {
	switch id {
	case AuditExplainable:
		return namespace == "sys_audit"
	case IdentityBusiness:
		return namespace == "sys_identity"
	case ResourceRegistry:
		return namespace == "sys_resource"
	case AuthorizationResource:
		return namespace == "sys_authz"
	case AdminControlPlane:
		return namespace == "sys_admin"
	default:
		return false
	}
}

func reservedBusinessPluginService(name string) bool {
	switch name {
	case ServiceAudit, ServiceIdentity, ServiceResourceRegistry, ServiceAuthorization, ServiceAuthorizationChecker, ServiceAuthorizationExplainer, ServiceAdmin:
		return false
	default:
		return false
	}
}
