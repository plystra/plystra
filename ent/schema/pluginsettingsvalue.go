package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type PluginSettingsValue struct {
	ent.Schema
}

func (PluginSettingsValue) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("plugin_id").NotEmpty(),
		stringDefaultField("space_id", ""),
		field.String("key").NotEmpty(),
		field.JSON("value", map[string]any{}),
		field.String("updated_by_user_id").Optional().Nillable(),
		field.String("updated_by_member_id").Optional().Nillable(),
		createdAt(),
		updatedAt(),
	}
}

func (PluginSettingsValue) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("plugin_id", "space_id", "key").Unique(),
	}
}
