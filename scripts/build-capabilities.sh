#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname "$script_dir")
workspace=$(dirname "$root")
out_root="$root/capabilities"

target_goos=${GOOS:-$(go env GOOS)}
target_goarch=${GOARCH:-$(go env GOARCH)}
target_cgo=${CGO_ENABLED:-0}

build_capability() {
  name=$1
  cmd=$2
  binary=$3

  repo="$workspace/$name"
  dest="$out_root/$name"
  output_binary=$binary

  if [ "$target_goos" = "windows" ]; then
    output_binary="$binary.exe"
  fi

  mkdir -p "$dest"
  cp -f "$repo/capability.yaml" "$dest/capability.yaml"
  rm -rf "$dest/migrations"
  cp -R "$repo/migrations" "$dest/migrations"

  (
    cd "$repo"
    env CGO_ENABLED="$target_cgo" GOOS="$target_goos" GOARCH="$target_goarch" \
      go build -o "$dest/$output_binary" "./$cmd"
  )
}

build_capability "system-audit" "cmd/system-audit" "system-audit"
build_capability "system-identity" "cmd/system-identity" "system-identity"
build_capability "system-resource-registry" "cmd/system-resource-registry" "system-resource-registry"
build_capability "system-authz" "cmd/system-authz" "system-authz"
build_capability "system-admin" "cmd/system-admin" "system-admin"

rm -f "$out_root/plystra.lock"

printf 'Built trusted system capabilities into %s\n' "$out_root"
