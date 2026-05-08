package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type AdminGrant struct {
	ent.Schema
}

func (AdminGrant) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("user_id").NotEmpty(),
		field.String("member_id").Optional().Nillable(),
		field.String("space_id").Optional().Nillable(),
		field.String("group_id").Optional().Nillable(),
		field.String("level").NotEmpty(),
		field.String("permission_key").NotEmpty(),
		statusField("active"),
		field.String("granted_by_user_id").Optional().Nillable(),
		field.String("granted_by_member_id").Optional().Nillable(),
		field.Time("expires_at").Optional().Nillable(),
		field.Time("revoked_at").Optional().Nillable(),
		field.String("revoked_reason").Optional().Nillable(),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (AdminGrant) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
		index.Fields("user_id", "status"),
		index.Fields("level", "status"),
		index.Fields("space_id"),
		index.Fields("group_id"),
		index.Fields("permission_key"),
	}
}
