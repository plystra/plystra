package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Group struct {
	ent.Schema
}

func (Group) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("space_id").NotEmpty(),
		field.String("parent_group_id").Optional().Nillable(),
		field.String("name").NotEmpty(),
		field.String("display_name").Optional().Nillable(),
		field.String("path").NotEmpty().Immutable().Validate(validateGroupPath),
		field.Int("depth").Default(0),
		field.Int("sort_order").Default(1000),
		statusField("active"),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (Group) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("space_id", "path").Unique(),
	}
}
