package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type UserMember struct {
	ent.Schema
}

func (UserMember) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("user_id").NotEmpty(),
		field.String("member_id").NotEmpty(),
		field.String("space_id").NotEmpty(),
		field.String("relation_type").NotEmpty(),
		statusField("active"),
		boolDefaultField("is_primary", false),
		field.Time("expires_at").Optional().Nillable(),
		field.String("linked_by_member_id").Optional().Nillable(),
		field.Time("linked_at").Optional().Nillable(),
		field.Time("revoked_at").Optional().Nillable(),
		field.String("revoked_reason").Optional().Nillable(),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}
