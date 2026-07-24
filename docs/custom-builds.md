# JSJ custom builds

The `Alpha` branch publishes a moving `Prerelease-Alpha` release containing:

- `mihomo-linux-amd64.gz` (GOAMD64 v1 for broad x86-64 compatibility)
- `mihomo-linux-arm64.gz`
- `mihomo-android-arm64-v8.gz`
- `checksums.txt`, `manifest.json`, and `version.txt`

## Linux update

```sh
sudo ./scripts/install-jsj-mihomo.sh
```

The installer verifies SHA-256, keeps the previous binary as
`/usr/local/bin/mihomo.bak`, and restarts an active `mihomo.service`.

Rollback:

```sh
sudo ./scripts/install-jsj-mihomo.sh --rollback
```

The release directory can be mirrored behind another web server by setting
`MIHOMO_BASE_URL`.
