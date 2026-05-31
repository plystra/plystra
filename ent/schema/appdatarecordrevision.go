package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type AppDataRecordRevision struct {
	ent.Schema
}

func (AppDataRecordRevision) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("record_id").NotEmpty(),
		field.String("space_id").NotEmpty(),
		field.String("model_id").NotEmpty(),
		field.String("model_key").NotEmpty(),
		field.Int("revision").Positive(),
		field.String("operation").NotEmpty(),
		field.String("actor_user_id").Optional().Nillable(),
		field.String("actor_member_id").Optional().Nillable(),
		field.String("actor_user_member_id").Optional().Nillable(),
		jsonObjectField("data"),
		metadataField(),
		createdAt(),
	}
}

func (AppDataRecordRevision) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("record_id", "revision").Unique(),
		index.Fields("space_id", "model_key", "record_id"),
		index.Fields("created_at"),
	}
}
