package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type AuthChallenge struct {
	ent.Schema
}

func (AuthChallenge) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("purpose").NotEmpty(),
		field.String("delivery_method").NotEmpty(),
		field.String("email").NotEmpty(),
		field.String("user_id").Optional().Nillable(),
		field.String("secret_hash").NotEmpty().Sensitive(),
		field.String("code_hash").Optional().Nillable().Sensitive(),
		field.String("redirect_url").Optional().Nillable(),
		field.String("request_ip").Optional().Nillable(),
		field.String("request_user_agent").Optional().Nillable(),
		intDefaultField("attempts", 0),
		intDefaultField("max_attempts", 5),
		statusField("pending"),
		field.Time("expires_at"),
		field.Time("consumed_at").Optional().Nillable(),
		field.Time("revoked_at").Optional().Nillable(),
		field.String("email_provider_message_id").Optional().Nillable(),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (AuthChallenge) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email", "purpose", "status"),
		index.Fields("secret_hash").Unique(),
		index.Fields("code_hash"),
		index.Fields("expires_at"),
	}
}
