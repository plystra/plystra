package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Role struct {
	ent.Schema
}

func (Role) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("space_id").NotEmpty(),
		field.String("key").NotEmpty(),
		field.String("name").NotEmpty(),
		field.String("description").Optional().Nillable(),
		statusField("active"),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (Role) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("space_id", "key").Unique(),
	}
}
