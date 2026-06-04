package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// ActionExecution is the Action Gateway execution journal. It records the
// lifecycle of a brokered controlled_action invocation (A3 / C2): Core owns the
// action entrypoint, separates authorization_decision from action_execution,
// and tracks succeeded / rejected / failed / result_unknown so that
// "allow != executed" is explicit and result_unknown can be reconciled.
type ActionExecution struct {
	ent.Schema
}

func (ActionExecution) Fields() []ent.Field {
	return []ent.Field{
		textID(),
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
		statusField("invoking"),
		field.String("handler_endpoint").Optional().Nillable(),
		field.Time("idempotency_expires_at"),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (ActionExecution) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("space_id", "capability", "operation", "idempotency_key").Unique(),
		index.Fields("space_id", "status"),
		index.Fields("correlation_id"),
		index.Fields("status", "idempotency_expires_at"),
	}
}
