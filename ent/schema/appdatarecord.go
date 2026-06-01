package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type AppDataRecord struct {
	ent.Schema
}

func (AppDataRecord) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("space_id").NotEmpty(),
		field.String("model_id").NotEmpty(),
		field.String("model_key").NotEmpty(),
		field.String("group_id").Optional().Nillable(),
		field.String("owner_member_id").Optional().Nillable(),
		field.String("display_name").Optional().Nillable(),
		stringDefaultField("visibility", "private"),
		statusField("active"),
		jsonObjectField("data"),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (AppDataRecord) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("space_id", "model_key", "id").Unique(),
		index.Fields("model_id"),
		index.Fields("space_id", "model_key", "status"),
		index.Fields("space_id", "model_key", "updated_at", "id").
			StorageKey("appdatarecord_space_model_updated_id").
			Annotations(entsql.DescColumns("updated_at", "id"), entsql.IndexWhere("deleted_at IS NULL")),
		index.Fields("space_id", "model_key", "created_at", "id").
			StorageKey("appdatarecord_space_model_created_id").
			Annotations(entsql.DescColumns("created_at", "id"), entsql.IndexWhere("deleted_at IS NULL")),
		index.Fields("space_id", "model_key", "visibility", "updated_at", "id").
			StorageKey("appdatarecord_space_model_visibility_updated_id").
			Annotations(entsql.DescColumns("updated_at", "id"), entsql.IndexWhere("deleted_at IS NULL")),
		index.Fields("space_id", "model_key", "status", "updated_at", "id").
			StorageKey("appdatarecord_space_model_status_updated_id").
			Annotations(entsql.DescColumns("updated_at", "id"), entsql.IndexWhere("deleted_at IS NULL")),
		index.Fields("space_id", "group_id"),
		index.Fields("space_id", "owner_member_id"),
	}
}
