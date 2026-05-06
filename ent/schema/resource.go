package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type Resource struct {
	ent.Schema
}

func (Resource) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("resource_type").NotEmpty(),
		field.String("external_id").Optional().Nillable(),
		field.String("space_id").NotEmpty(),
		field.String("group_id").Optional().Nillable(),
		field.String("owner_member_id").Optional().Nillable(),
		field.String("display_name").Optional().Nillable(),
		stringDefaultField("visibility", "private"),
		metadataField(),
		statusField("active"),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}
