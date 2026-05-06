package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type AuditEventType struct {
	ent.Schema
}

func (AuditEventType) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("key").NotEmpty(),
		field.String("plugin_id").Optional().Nillable(),
		field.String("display_name").NotEmpty(),
		field.String("description").Optional().Nillable(),
		stringDefaultField("risk_level", "normal"),
		boolDefaultField("default_audit", true),
		metadataField(),
		createdAt(),
		updatedAt(),
	}
}

func (AuditEventType) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key").Unique(),
	}
}
