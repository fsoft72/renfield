# Changes

## 2026-10-21

- Added the renfield design document (docs/superpowers/specs/2026-10-21-renfield-design.md).
- Scaffolded the crate (lib + bin), config home resolution, machine identity (self signed Ed25519) and the registry and authorized key stores.
- Added the framed wire protocol (u32 length, kind byte, body) and mutual TLS 1.3 with peers pinned by certificate fingerprint, plus the error type with reserved exit codes.
