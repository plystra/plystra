package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Plugin struct {
	ent.Schema
}

func (Plugin) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("key").NotEmpty(),
		field.String("name").NotEmpty(),
		field.String("description").Optional().Nillable(),
		field.String("version").NotEmpty(),
		stringDefaultField("type", "plugin"),
		stringDefaultField("scope", "public"),
		field.String("app_id").Optional().Nillable(),
		field.String("trust_bundle_id").Optional().Nillable(),
		stringDefaultField("source", "official"),
		statusField("installed"),
		field.JSON("manifest", map[string]any{}),
		createdAt(),
		updatedAt(),
	}
}

func (Plugin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key").Unique(),
		index.Fields("type", "scope", "status"),
		index.Fields("app_id", "status"),
		index.Fields("trust_bundle_id", "status"),
	}
}
