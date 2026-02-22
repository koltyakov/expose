# Temporary Host Allocation

When `--domain` is not set, `expose http` uses temporary host allocation.

## Allocation behavior

- Wildcard TLS active: a randomized temporary host (6-char slug) is allocated.
- Wildcard TLS not active: server first tries a deterministic host from `client_hostname + ":" + local_port`:
  - `sha1(client_hostname:local_port)` -> base32 lowercase -> first 6 chars
  - example shape: `k3xnz3.example.com`
  - on collision, server falls back to randomized 6-char host

## Why randomization exists

- avoids users accidentally claiming memorable names in temporary mode
- reduces hostname collisions across clients
- discourages abuse of automatic certificate issuance for disposable temporary hosts
- keeps temporary endpoints disposable
