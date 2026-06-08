package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type ApiKey struct {
	ent.Schema
}

func (ApiKey) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("name").NotEmpty(),
		field.String("key_prefix").NotEmpty().Immutable(),
		field.String("key_hash").NotEmpty().Sensitive(),
		field.String("level").NotEmpty(),
		field.String("space_id").Optional().Nillable(),
		field.String("group_id").Optional().Nillable(),
		field.JSON("permission_keys", []string{}).Annotations(entsql.DefaultExpr("'[]'::jsonb")),
		statusField("active"),
		field.Time("expires_at").Optional().Nillable(),
		field.Time("last_used_at").Optional().Nillable(),
		field.String("created_by_user_id").Optional().Nillable(),
		field.String("created_by_member_id").Optional().Nillable(),
		field.String("provider_runtime_plugin_id").Optional().Nillable(),
		field.Time("revoked_at").Optional().Nillable(),
		field.String("revoked_by_user_id").Optional().Nillable(),
		field.String("revoked_reason").Optional().Nillable(),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (ApiKey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key_hash").Unique(),
		index.Fields("key_prefix"),
		index.Fields("status"),
		index.Fields("level", "status"),
		index.Fields("space_id"),
		index.Fields("group_id"),
		index.Fields("created_by_user_id"),
		index.Fields("provider_runtime_plugin_id"),
	}
}
