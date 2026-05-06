package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type PluginSettingsDefinition struct {
	ent.Schema
}

func (PluginSettingsDefinition) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("plugin_id").NotEmpty(),
		field.String("key").NotEmpty(),
		field.String("value_type").NotEmpty(),
		field.JSON("default_value", map[string]any{}).Optional(),
		field.String("description").Optional().Nillable(),
		stringDefaultField("scope", "space"),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (PluginSettingsDefinition) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("plugin_id", "key", "scope").Unique(),
	}
}
