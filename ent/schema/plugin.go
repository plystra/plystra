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
	}
}
