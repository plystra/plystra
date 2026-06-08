package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type CapabilityProviderBinding struct {
	ent.Schema
}

func (CapabilityProviderBinding) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("space_id").NotEmpty(),
		field.String("capability").NotEmpty(),
		field.String("operation").NotEmpty(),
		field.String("provider_plugin_id").NotEmpty(),
		field.String("endpoint").NotEmpty(),
		field.String("operation_path").Optional().Nillable(),
		intDefaultField("binding_epoch", 1),
		statusField("active"),
		jsonObjectField("identity"),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (CapabilityProviderBinding) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("space_id", "capability", "operation").Unique(),
		index.Fields("space_id", "provider_plugin_id", "status"),
		index.Fields("capability", "operation", "status"),
	}
}
