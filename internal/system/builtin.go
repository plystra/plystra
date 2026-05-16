package system

import (
	"github.com/plystra/plystra/internal/authz"
	"github.com/plystra/plystra/internal/kernel/contracts"
	"github.com/plystra/plystra/internal/resources"
	systemadmin "github.com/plystra/plystra/internal/system/admin"
	systemaudit "github.com/plystra/plystra/internal/system/audit"
	systemauthz "github.com/plystra/plystra/internal/system/authz"
	systemidentity "github.com/plystra/plystra/internal/system/identity"
	systemresource "github.com/plystra/plystra/internal/system/resource_registry"
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
