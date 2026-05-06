package schema

import (
	"context"
	"errors"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type AuditLog struct {
	ent.Schema
}

func (AuditLog) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("space_id").NotEmpty(),
		field.String("actor_user_id").Optional().Nillable(),
		field.String("actor_member_id").Optional().Nillable(),
		field.String("actor_user_member_id").Optional().Nillable(),
		field.String("action").NotEmpty(),
		field.String("resource_type").NotEmpty(),
		field.String("resource_id").NotEmpty(),
		field.String("decision").NotEmpty(),
		field.String("deny_code").Optional().Nillable(),
		field.JSON("trace", map[string]any{}),
		field.String("request_id").Optional().Nillable(),
		field.String("ip_address").Optional().Nillable(),
		field.String("user_agent").Optional().Nillable(),
		createdAt(),
	}
}

func (AuditLog) Hooks() []ent.Hook {
	return []ent.Hook{
		func(next ent.Mutator) ent.Mutator {
			return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
				switch m.Op() {
				case ent.OpUpdate, ent.OpUpdateOne, ent.OpDelete, ent.OpDeleteOne:
					return nil, errors.New("audit logs are append-only")
				default:
					return next.Mutate(ctx, m)
				}
			})
		},
	}
}
