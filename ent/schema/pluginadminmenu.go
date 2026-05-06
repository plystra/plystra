package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type PluginAdminMenu struct {
	ent.Schema
}

func (PluginAdminMenu) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("plugin_id").NotEmpty(),
		field.String("label").NotEmpty(),
		field.String("path").NotEmpty(),
		field.String("icon").Optional().Nillable(),
		field.String("required_permission").Optional().Nillable(),
		intDefaultField("sort_order", 1000),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}
