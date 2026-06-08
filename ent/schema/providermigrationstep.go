package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type ProviderMigrationStep struct {
	ent.Schema
}

func (ProviderMigrationStep) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("revision_id").NotEmpty(),
		field.String("provider_plugin_id").NotEmpty(),
		field.Int("step_index"),
		field.String("statement_hash").NotEmpty(),
		field.String("statement_kind").NotEmpty(),
		statusField("planned"),
		boolDefaultField("destructive", false),
		boolDefaultField("backfill", false),
		boolDefaultField("tenant_scope_reviewed", false),
		boolDefaultField("rls_bypass", false),
		field.String("precondition").Optional().Nillable(),
		field.String("recovery_action").Optional().Nillable(),
		field.Time("started_at").Optional().Nillable(),
		field.Time("finished_at").Optional().Nillable(),
		field.String("error").Optional().Nillable(),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (ProviderMigrationStep) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("revision_id", "step_index").Unique(),
		index.Fields("provider_plugin_id", "status"),
		index.Fields("statement_hash"),
	}
}
