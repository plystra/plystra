package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type MemberRole struct {
	ent.Schema
}

func (MemberRole) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("member_id").NotEmpty(),
		field.String("role_id").NotEmpty(),
		field.String("space_id").NotEmpty(),
		field.String("scope_anchor_group_id").Optional().Nillable(),
		statusField("active"),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (MemberRole) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("member_id", "role_id", "scope_anchor_group_id").Unique(),
	}
}
