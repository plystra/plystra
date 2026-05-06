package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type ResourceAction struct {
	ent.Schema
}

func (ResourceAction) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("resource_type_id").NotEmpty(),
		field.String("key").NotEmpty(),
		field.String("display_name").NotEmpty(),
		field.String("description").Optional().Nillable(),
		stringDefaultField("risk_level", "normal"),
		boolDefaultField("audit_default", true),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (ResourceAction) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("resource_type_id", "key").Unique(),
	}
}
