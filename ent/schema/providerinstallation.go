package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type ProviderInstallation struct {
	ent.Schema
}

func (ProviderInstallation) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("provider_plugin_id").NotEmpty(),
		field.String("plugin_type").NotEmpty(),
		field.String("plugin_scope").NotEmpty(),
		field.String("app_id").Optional().Nillable(),
		field.String("trust_bundle_id").Optional().Nillable(),
		field.String("schema_name").NotEmpty(),
		field.String("migrator_role").NotEmpty(),
		field.String("runtime_role").NotEmpty(),
		intDefaultField("schema_version", 0),
		intDefaultField("runtime_schema_min", 0),
		intDefaultField("runtime_schema_max", 0),
		intDefaultField("runtime_schema_preferred", 0),
		boolDefaultField("rls_required", true),
		boolDefaultField("zero_ddl_runtime", true),
		boolDefaultField("mutation_journal_required", false),
		statusField("planned"),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (ProviderInstallation) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("provider_plugin_id").Unique(),
		index.Fields("schema_name"),
		index.Fields("runtime_role").Unique(),
		index.Fields("migrator_role").Unique(),
		index.Fields("plugin_type", "plugin_scope", "status"),
		index.Fields("app_id", "status"),
		index.Fields("trust_bundle_id", "status"),
	}
}
