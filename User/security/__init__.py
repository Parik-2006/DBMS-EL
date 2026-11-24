"""
Shared security utilities for MaliciousBot (Phase 1).

- outbound:   SSRF-safe outbound URL policy and DNS-pinned HTTP/TLS transport.
- redaction:  secret / sensitive-header redaction for logs and forensic storage.
- ratelimit:  cache-backed fixed-window rate limiting.
- api:        JSON API authentication / authorization helpers.
- tenancy:    authoritative tenant identity derived from server-side context.
- headers:    security-header middleware (Content-Security-Policy etc.).
"""
