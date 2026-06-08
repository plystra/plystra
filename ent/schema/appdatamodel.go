package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type AppDataModel struct {
	ent.Schema
}

func (AppDataModel) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("space_id").NotEmpty(),
		field.String("key").NotEmpty(),
		field.String("display_name").NotEmpty(),
		field.String("description").Optional().Nillable(),
		stringDefaultField("source", "app"),
		field.String("owner_plugin_key").Optional().Nillable(),
		field.String("declared_resource_key").Optional().Nillable(),
		statusField("active"),
		jsonObjectField("schema"),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (AppDataModel) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("space_id", "key").Unique(),
		index.Fields("space_id", "status"),
		index.Fields("space_id", "owner_plugin_key"),
		index.Fields("owner_plugin_key", "declared_resource_key"),
		index.Fields("key"),
	}
}
