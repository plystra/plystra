# System Capabilities

System capabilities are built-in privileged modules loaded by the kernel during process startup.

Current capabilities:

- `audit.explainable`
- `identity.business`
- `resource.registry`
- `authorization.resource`
- `admin.control_plane`

Each capability declares a manifest, registers services, registers API route metadata, registers migration ownership metadata, and exposes lifecycle hooks. Business plugins remain governed extensions and cannot replace these core system services.
