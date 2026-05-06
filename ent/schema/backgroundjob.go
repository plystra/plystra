package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
)

type BackgroundJob struct {
	ent.Schema
}

func (BackgroundJob) Fields() []ent.Field {
	return []ent.Field{
		textID(),
		field.String("job_type").NotEmpty(),
		field.JSON("payload", map[string]any{}),
		statusField("pending"),
		intDefaultField("attempts", 0),
		intDefaultField("max_attempts", 5),
		field.Time("run_after").Default(time.Now).Annotations(entsql.Default("now()")),
		field.String("last_error").Optional().Nillable(),
		createdAt(),
		updatedAt(),
	}
}
