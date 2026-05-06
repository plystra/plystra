package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type ResourceMapping struct {
	ent.Schema
}

func (ResourceMapping) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("resource_type_id").NotEmpty(),
		stringDefaultField("storage_kind", "internal_table"),
		field.String("table_name").Optional().Nillable(),
		stringDefaultField("id_field", "id"),
		stringDefaultField("space_field", "space_id"),
		field.String("group_field").Optional().Nillable(),
		field.String("owner_member_field").Optional().Nillable(),
		field.String("visibility_field").Optional().Nillable(),
		field.String("metadata_field").Optional().Nillable(),
		statusField("active"),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (ResourceMapping) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("resource_type_id").Unique(),
	}
}
