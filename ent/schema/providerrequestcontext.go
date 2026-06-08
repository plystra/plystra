package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type ProviderRequestContext struct {
	ent.Schema
}

func (ProviderRequestContext) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("token_hash").NotEmpty().Immutable().Sensitive(),
		field.String("provider_plugin_id").NotEmpty(),
		field.String("space_id").NotEmpty(),
		field.String("actor_user_id").Optional().Nillable(),
		field.String("actor_member_id").Optional().Nillable(),
		field.String("actor_user_member_id").Optional().Nillable(),
		field.String("authorization_decision_id").Optional().Nillable(),
		field.String("request_id").Optional().Nillable(),
		field.String("purpose").Optional().Nillable(),
		statusField("active"),
		field.Time("expires_at"),
		field.Time("revoked_at").Optional().Nillable(),
		field.String("revoked_reason").Optional().Nillable(),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (ProviderRequestContext) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("token_hash").Unique(),
		index.Fields("provider_plugin_id", "status"),
		index.Fields("space_id", "status"),
		index.Fields("expires_at"),
		index.Fields("authorization_decision_id"),
	}
}
