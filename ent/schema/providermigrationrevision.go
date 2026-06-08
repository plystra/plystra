package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type ProviderMigrationRevision struct {
	ent.Schema
}

func (ProviderMigrationRevision) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("provider_plugin_id").NotEmpty(),
		field.String("installation_id").NotEmpty(),
		field.String("revision").NotEmpty(),
		field.String("bundle_hash").NotEmpty(),
		field.String("schema_name").NotEmpty(),
		intDefaultField("from_schema_version", 0),
		intDefaultField("to_schema_version", 0),
		statusField("planned"),
		boolDefaultField("destructive", false),
		boolDefaultField("rls_bypass", false),
		boolDefaultField("requires_manual_review", false),
		field.String("reviewed_by_user_id").Optional().Nillable(),
		field.Time("reviewed_at").Optional().Nillable(),
		field.Time("started_at").Optional().Nillable(),
		field.Time("finished_at").Optional().Nillable(),
		field.String("last_error").Optional().Nillable(),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (ProviderMigrationRevision) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("provider_plugin_id", "revision").Unique(),
		index.Fields("installation_id", "status"),
		index.Fields("provider_plugin_id", "status"),
		index.Fields("bundle_hash"),
	}
}
