package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type User struct {
	ent.Schema
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("email").NotEmpty(),
		field.String("username").Optional().Nillable(),
		field.String("phone").Optional().Nillable(),
		statusField("active"),
		field.String("password_hash").Optional().Nillable().Sensitive(),
		field.Time("password_changed_at").Optional().Nillable(),
		field.Time("last_login_at").Optional().Nillable(),
		metadataField(),
		createdAt(),
		updatedAt(),
		deletedAt(),
	}
}

func (User) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email").Unique(),
	}
}
