# Request ID Envelope Compatibility

## Document Status

| Field | Value |
|---|---|
| Product | Plystra |
| Version | v1.0 |
| Document Type | Compatibility note |
| Scope | API response envelope |
| Status | Active compatibility policy |

---

## 1. Purpose

This document defines Plystra v1.0 request ID response compatibility behavior.

Earlier API designs used request ID under:

```json
{
  "meta": {
    "request_id": "req_..."
  }
}
```

The v1.0 Core PRD standardizes top-level request ID:

```json
{
  "request_id": "req_..."
}
```

To preserve compatibility and support newer clients, v1.0 returns both fields where the response envelope supports them.

---

## 2. Compatibility Policy

For v1.0:

```text
Return top-level request_id.
Return meta.request_id for compatibility.
Both values must be identical.
```

Example:

```json
{
  "data": {
    "decision": "allow"
  },
  "request_id": "req_01HZY...",
  "meta": {
    "request_id": "req_01HZY..."
  }
}
```

This allows:

```text
new clients to read response.request_id
older clients to read response.meta.request_id
```

---

## 3. Why Both Fields Exist

Plystra v1.0 aligns the public API with the new Core PRD while avoiding unnecessary client breakage.

The compatibility behavior exists because:

```text
older docs or clients may already expect meta.request_id
new v1.0 docs expect top-level request_id
request_id is operationally important for debugging
request_id must correlate API responses, logs, and AuditLog records
```

Returning both fields is a low-cost compatibility bridge.

---

## 4. Response Envelope Rules

## 4.1 Success Response

Preferred v1.0 shape:

```json
{
  "data": {},
  "request_id": "req_...",
  "meta": {
    "request_id": "req_..."
  }
}
```

## 4.2 Error Response

Preferred v1.0 shape:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request body",
    "details": {}
  },
  "request_id": "req_...",
  "meta": {
    "request_id": "req_..."
  }
}
```

## 4.3 Authorization Deny Response

Preferred v1.0 shape:

```json
{
  "error": {
    "code": "AUTHORIZATION_DENIED",
    "message": "The action is not allowed.",
    "deny_code": "SCOPE_OUT_OF_BOUNDS",
    "trace_id": "trc_..."
  },
  "request_id": "req_...",
  "meta": {
    "request_id": "req_..."
  }
}
```

---

## 5. Required Invariants

The following must always be true:

```text
top-level request_id is present
meta.request_id is present when compatibility mode is enabled
top-level request_id equals meta.request_id
request_id is a string
request_id is stable for the lifetime of the request
request_id appears in structured logs
request_id can be stored in AuditLog when available
```

---

## 6. Logging Correlation

The same request ID should appear in:

```text
API response
structured request log
error log
panic recovery log
AuditLog request_id field when an audited action occurs
```

Example log fields:

```json
{
  "level": "info",
  "request_id": "req_01HZY...",
  "method": "POST",
  "path": "/api/v1/authz/check",
  "status": 200,
  "latency_ms": 12
}
```

Example AuditLog field:

```json
{
  "id": "aud_...",
  "request_id": "req_01HZY...",
  "decision": "allow"
}
```

---

## 7. OpenAPI Requirements

OpenAPI v1.0 must document both fields if both are returned.

At minimum, response schemas should include:

```text
request_id
meta.request_id
```

If the schema uses a shared envelope component, the component must include both fields.

Example schema concept:

```yaml
ResponseEnvelope:
  type: object
  properties:
    data:
      type: object
    request_id:
      type: string
    meta:
      type: object
      properties:
        request_id:
          type: string
```

---

## 8. Client Guidance

New clients should prefer:

```text
response.request_id
```

Older clients may continue using:

```text
response.meta.request_id
```

Recommended client logic:

```ts
const requestId = response.request_id ?? response.meta?.request_id
```

Clients should not assume `meta` contains anything other than compatibility fields unless documented elsewhere.

---

## 9. Testing Requirements

v1.0 tests must verify:

```text
success responses include top-level request_id
error responses include top-level request_id
authorization deny responses include top-level request_id
meta.request_id exists if compatibility mode is enabled
top-level request_id equals meta.request_id
request_id appears in structured logs
request_id can be written to AuditLog
OpenAPI documents request_id fields
```

---

## 10. Deprecation Policy

For v1.0:

```text
meta.request_id is supported.
```

For v1.x:

```text
meta.request_id should remain supported unless a formal deprecation policy is published.
```

For v2.0:

```text
The project may decide whether to remove meta.request_id.
Removal requires advance notice in release notes and migration guide.
```

No v1.x release should remove `meta.request_id` without explicit deprecation documentation.

---

## 11. Release Notes Wording

The v1.0 release notes should include:

```text
Plystra v1.0 returns request_id at the top level of API responses while preserving meta.request_id for compatibility with older clients. Both values are identical. New clients should prefer the top-level request_id.
```

---

## 12. Summary

Plystra v1.0 returns both:

```text
request_id
meta.request_id
```

This is intentional.

It provides a smooth compatibility path while standardizing the v1.0 response envelope.
