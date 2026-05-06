package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type TemplateInstallation struct {
	ent.Schema
}

func (TemplateInstallation) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("template_id").NotEmpty(),
		field.String("template_version").NotEmpty(),
		field.String("space_id").Optional().Nillable(),
		statusField("installed"),
		field.JSON("manifest_snapshot", map[string]any{}),
		field.String("installed_by_user_id").Optional().Nillable(),
		field.String("installed_by_member_id").Optional().Nillable(),
		createdAt(),
	}
}
