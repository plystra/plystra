package schema

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
)

var groupPathPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

func textID() ent.Field {
	return field.String("id").NotEmpty().Immutable()
}

func statusField(defaultValue string) ent.Field {
	return stringDefaultField("status", defaultValue)
}

func stringDefaultField(name, defaultValue string) ent.Field {
	return field.String(name).Default(defaultValue).Annotations(entsql.DefaultExpr(sqlStringLiteral(defaultValue)))
}

func boolDefaultField(name string, defaultValue bool) ent.Field {
	return field.Bool(name).Default(defaultValue).Annotations(entsql.DefaultExpr(strconv.FormatBool(defaultValue)))
}

func intDefaultField(name string, defaultValue int) ent.Field {
	return field.Int(name).Default(defaultValue).Annotations(entsql.DefaultExpr(strconv.Itoa(defaultValue)))
}

func createdAt() ent.Field {
	return field.Time("created_at").Default(time.Now).Immutable().Annotations(entsql.DefaultExpr("now()"))
}

func updatedAt() ent.Field {
	return field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now).Annotations(entsql.DefaultExpr("now()"))
}

func deletedAt() ent.Field {
	return field.Time("deleted_at").Optional().Nillable()
}

func metadataField() ent.Field {
	return field.JSON("metadata", map[string]any{}).Optional().Annotations(entsql.DefaultExpr("'{}'::jsonb"))
}

func jsonObjectField(name string) ent.Field {
	return field.JSON(name, map[string]any{}).Annotations(entsql.DefaultExpr("'{}'::jsonb"))
}

func sqlStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func validateGroupPath(path string) error {
	path = strings.TrimSpace(path)
	if !groupPathPattern.MatchString(path) {
		return fmt.Errorf("group path %q must match %s", path, groupPathPattern.String())
	}
	return nil
}
