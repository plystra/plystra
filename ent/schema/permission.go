package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Permission struct {
	ent.Schema
}

func (Permission) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("resource").NotEmpty(),
		field.String("action").NotEmpty(),
		field.String("scope").NotEmpty(),
		field.String("description").Optional().Nillable(),
		statusField("active"),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (Permission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("resource", "action", "scope").Unique(),
	}
}
