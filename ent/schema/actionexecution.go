package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type ActionExecution struct {
	ent.Schema
}

func (ActionExecution) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("space_id").NotEmpty(),
		field.String("capability").NotEmpty(),
		field.String("operation").NotEmpty(),
		field.String("resource_type").NotEmpty(),
		field.String("resource_id").NotEmpty(),
		field.String("resource_action").NotEmpty(),
		field.String("principal_user_id").Optional().Nillable(),
		field.String("principal_member_id").Optional().Nillable(),
		field.String("principal_user_member_id").Optional().Nillable(),
		field.String("executor_plugin_id").NotEmpty(),
		field.String("provider_plugin_id").NotEmpty(),
		field.String("decision_id").Optional().Nillable(),
		field.String("correlation_id").NotEmpty(),
		field.String("idempotency_key").NotEmpty(),
		statusField("running"),
		field.Time("started_at"),
		field.Time("timeout_at"),
		field.Time("completed_at").Optional().Nillable(),
		jsonObjectField("resource"),
		field.JSON("input_summary", map[string]any{}).Optional(),
		field.JSON("result_ref", map[string]any{}).Optional(),
		field.String("error_code").Optional().Nillable(),
		field.String("error_message").Optional().Nillable(),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (ActionExecution) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("space_id", "executor_plugin_id", "capability", "operation", "idempotency_key").Unique(),
		index.Fields("space_id", "provider_plugin_id", "capability", "operation", "idempotency_key").Unique(),
		index.Fields("space_id", "resource_type", "resource_id"),
		index.Fields("space_id", "capability", "operation", "status"),
		index.Fields("status", "started_at"),
		index.Fields("status", "timeout_at"),
		index.Fields("correlation_id"),
	}
}
