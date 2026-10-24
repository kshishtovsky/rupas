# build/windivert — WinDivert 2.2 runtime binaries

Pinned driver artifacts for the `pkg/windivert` binding (SYSTEM_DESIGN §3.1,
ADR-2). Copied verbatim from the installed distribution at
`E:\zapret-discord-youtube-1.10.2\zapret-discord-youtube-1.10.2\bin\`.

| File          | SHA256 |
|---------------|--------|
| WinDivert.dll | `c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2` |
| WinDivert64.sys | `8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2` |

Driver service: `WinDivert` (KERNEL_DRIVER), reports version **2.2** via
`WinDivertGetParam`.

## Empirically verified behavior of this exact DLL (PE export table + live probes)

- Exports are the **stock WinDivert 2.2 API set** (30 exports):
  `WinDivertOpen/Close/Recv/RecvEx/Send/SendEx/Shutdown/SetParam/GetParam`
  plus the `WinDivertHelper*` userspace functions.
- **No** `WinDivertRecvBatch` and **no** `WinDivertRedirect*` exports
  (those exist only in the Flowseal/zapret-winws fork). `RecvBatch` in
  `pkg/windivert` is therefore implemented over the official
  `WinDivertRecvEx`, recovering per-packet boundaries from IP header
  total-length fields.
- Layer 5 (`LayerRedirect`) is rejected by `WinDivertOpen` with
  `ERROR_INVALID_PARAMETER` (87).
- The filter compiler rejects `in {...}` sets, CIDR mask literals
  (`a.b.c.d/nn`) and **all IPv6 address literals** (the IPv6 stack is
  stripped in this build). Use explicit `>=`/`<=` ranges; see
  `FilterBuilder`.
- Filter strings are plain C strings (`const char *`), not UTF-16, and are
  capped at ~8 KiB ("Filter expression too long" beyond).

## Deployment note

`syscall.NewLazyDLL("WinDivert.dll")` resolves via the standard DLL search
path (application directory, system dirs, PATH). Ship `WinDivert.dll` next
to the rupas executable (or add this directory to PATH); the driver service
must be installed and running (requires elevation).
