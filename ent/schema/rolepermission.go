package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type RolePermission struct {
	ent.Schema
}

func (RolePermission) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("role_id").NotEmpty(),
		field.String("permission_id").NotEmpty(),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (RolePermission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_id", "permission_id").Unique(),
		index.Fields("permission_id"),
	}
}
