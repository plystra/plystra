package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type CapabilityGrant struct {
	ent.Schema
}

func (CapabilityGrant) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("token_hash").NotEmpty().Sensitive(),
		field.String("space_id").NotEmpty(),
		field.String("capability").NotEmpty(),
		field.String("operation").NotEmpty(),
		field.String("principal_user_id").Optional().Nillable(),
		field.String("principal_member_id").Optional().Nillable(),
		field.String("principal_user_member_id").Optional().Nillable(),
		field.String("caller_plugin_id").NotEmpty(),
		field.String("target_provider_id").NotEmpty(),
		field.String("parent_grant_id").Optional().Nillable(),
		field.String("decision_id").Optional().Nillable(),
		field.String("correlation_id").NotEmpty(),
		field.String("idempotency_key").NotEmpty(),
		field.String("target_idempotency_key").NotEmpty(),
		intDefaultField("binding_epoch", 1),
		statusField("active"),
		stringDefaultField("outcome_status", "pending"),
		field.Time("expected_outcome_by"),
		field.Time("expires_at"),
		field.Time("revoked_at").Optional().Nillable(),
		field.String("revoked_reason").Optional().Nillable(),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (CapabilityGrant) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("token_hash").Unique(),
		index.Fields("space_id", "caller_plugin_id", "capability", "operation", "idempotency_key").Unique(),
		index.Fields("space_id", "target_provider_id", "capability", "operation", "target_idempotency_key").Unique(),
		index.Fields("space_id", "capability", "operation"),
		index.Fields("target_provider_id", "status"),
		index.Fields("parent_grant_id"),
		index.Fields("status", "expires_at"),
		index.Fields("outcome_status", "expected_outcome_by"),
	}
}
