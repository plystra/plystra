package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/plystra/plystra/internal/api"
)

func main() {
	out := flag.String("out", "openapi", "directory for generated OpenAPI artifacts")
	version := flag.String("version", api.OpenAPIVersion, "Core version to write into OpenAPI info.version")
	flag.Parse()

	if err := api.WriteOpenAPIFiles(*out, *version); err != nil {
		fmt.Fprintf(os.Stderr, "generate OpenAPI: %v\n", err)
		os.Exit(1)
	}
}
