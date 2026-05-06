# Core API

Plystra Core exposes a pre-1.0 `/api/v1` HTTP API.

All successful responses use:

```json
{
  "data": {},
  "meta": {
    "request_id": "req_..."
  }
}
```

List responses also include:

```json
{
  "pagination": {
    "limit": 50,
    "cursor": null,
    "has_more": false
  }
}
```

Errors use:

```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "The request body is invalid.",
    "details": [],
    "request_id": "req_..."
  }
}
```

## Implemented Endpoint Groups

- `/api/v1/system`
- `/api/v1/console/overview`
- `/api/v1/authz`
- `/api/v1/audit`
- `/api/v1/spaces`
- `/api/v1/groups`
- `/api/v1/members`
- `/api/v1/user-members`
- `/api/v1/roles`
- `/api/v1/permissions`
- `/api/v1/resources`
- `/api/v1/data`
- `/api/v1/resource-types`
- `/api/v1/plugins`
- `/api/v1/templates`

## Recent v1.0-oriented additions

- `GET /api/v1/templates`
- `GET /api/v1/templates/{template_id}`
- `POST /api/v1/templates/{template_id}/preview-install`
- `POST /api/v1/templates/{template_id}/install`
- `POST /api/v1/plugins/install`
- `POST /api/v1/plugins/{plugin_id}/enable`
- `POST /api/v1/plugins/{plugin_id}/disable`
- `POST /api/v1/plugins/{plugin_id}/uninstall`
- `GET/PATCH /api/v1/plugins/{plugin_id}/settings`
- `GET /api/v1/data/tables`
- `GET /api/v1/data/rows/{resource_type}`
- `POST /api/v1/data/rows/{resource_type}`
- `PATCH /api/v1/data/rows/{resource_type}/{resource_id}`
- `DELETE /api/v1/data/rows/{resource_type}/{resource_id}`

Data Console mutations currently support `internal_table` mappings backed by the Core `resources` table. Each mutation runs an authorization check against the requested row action and returns the authorization decision alongside the changed row.

OpenAPI artifacts live in:

```text
openapi/plystra.v0.6.0.json
openapi/plystra.v0.6.0.yaml
```

The API is still pre-1.0 and may change before the stable release. v1.0 will freeze response envelopes, deny code semantics, and required audit trace fields.
