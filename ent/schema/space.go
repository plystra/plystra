package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type Space struct {
	ent.Schema
}

func (Space) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("name").NotEmpty(),
		field.String("slug").Optional().Nillable(),
		stringDefaultField("type", "custom"),
		statusField("active"),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}
