package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Session struct {
	ent.Schema
}

func (Session) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("user_id").NotEmpty(),
		field.String("active_space_id").Optional().Nillable(),
		field.String("active_member_id").Optional().Nillable(),
		field.String("active_user_member_id").Optional().Nillable(),
		field.String("access_token_hash").NotEmpty().Sensitive(),
		field.String("refresh_token_hash").NotEmpty().Sensitive(),
		field.Time("expires_at"),
		field.Time("refresh_expires_at"),
		field.Time("revoked_at").Optional().Nillable(),
		field.String("ip").Optional().Nillable(),
		field.String("user_agent").Optional().Nillable(),
		createdAt(),
		updatedAt(),
	}
}

func (Session) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
		index.Fields("access_token_hash").Unique(),
		index.Fields("refresh_token_hash").Unique(),
	}
}
