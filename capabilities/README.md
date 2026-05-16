# Trusted System Capabilities

`plystrad` loads official system capabilities at startup from this directory when `capabilities/system-capabilities.yaml` is present.

This is intentionally a trusted local runtime module model:

- local binaries only
- manifest and lockfile verification
- startup-time loading
- no marketplace
- no hot unload
- no third-party replacement of identity, authorization, audit, resource registry, or admin control-plane services

Build the local sidecars with:

```bash
./scripts/build-capabilities.sh
```

On Windows PowerShell:

```powershell
.\scripts\build-capabilities.ps1
```
