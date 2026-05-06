package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type ResourceType struct {
	ent.Schema
}

func (ResourceType) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("key").NotEmpty(),
		field.String("display_name").NotEmpty(),
		field.String("description").Optional().Nillable(),
		statusField("active"),
		stringDefaultField("source", "core"),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (ResourceType) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key").Unique(),
	}
}
