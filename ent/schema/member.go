package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type Member struct {
	ent.Schema
}

func (Member) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("space_id").NotEmpty(),
		field.String("display_name").NotEmpty(),
		stringDefaultField("member_type", "human"),
		statusField("active"),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}
