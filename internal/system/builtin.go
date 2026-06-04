package system

import (
	"github.com/plystra/core/internal/authz"
	"github.com/plystra/core/internal/kernel/contracts"
	"github.com/plystra/core/internal/resources"
	systemadmin "github.com/plystra/core/internal/system/admin"
	systemaudit "github.com/plystra/core/internal/system/audit"
	systemauthz "github.com/plystra/core/internal/system/authz"
	systemidentity "github.com/plystra/core/internal/system/identity"
	systemresource "github.com/plystra/core/internal/system/resource_registry"
)

func BuiltInCapabilities(authzStore authz.Store, resourceStore resources.Store) []contracts.SystemCapability {
	return []contracts.SystemCapability{
		systemaudit.NewCapability(authzStore),
		systemidentity.NewCapability(authzStore),
		systemresource.NewCapability(resourceStore, authzStore),
		systemauthz.NewCapability(authzStore),
		systemadmin.NewCapability(),
	}
}
