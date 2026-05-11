package main

import (
	"path/filepath"
	"testing"

	"ariga.io/atlas/sql/migrate"
)

func TestMigrationRecordMatchesLegacyAndAtlasChecksums(t *testing.T) {
	file := migrationFile{Checksum: "legacy-sha256", AtlasHash: "atlas-hash"}

	tests := []struct {
		name   string
		record migrationRecord
		want   bool
	}{
		{name: "legacy checksum", record: migrationRecord{Checksum: "legacy-sha256"}, want: true},
		{name: "atlas checksum", record: migrationRecord{Checksum: "atlas-hash"}, want: true},
		{name: "atlas checksum with h1 prefix", record: migrationRecord{Checksum: "h1:atlas-hash"}, want: true},
		{name: "mismatch", record: migrationRecord{Checksum: "different"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.record.matches(file); got != tt.want {
				t.Fatalf("matches() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestAtlasMigrationDirectoryIsValid(t *testing.T) {
	dir, err := migrate.NewLocalDir(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("NewLocalDir() error = %v", err)
	}
	if err := migrate.Validate(dir); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	files, err := dir.Files()
	if err != nil {
		t.Fatalf("Files() error = %v", err)
	}
	for _, file := range files {
		if _, err := file.Stmts(); err != nil {
			t.Fatalf("%s Stmts() error = %v", file.Name(), err)
		}
	}
}
