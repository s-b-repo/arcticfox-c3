# Architecture

## Data Flow

```
Operator ──► API/control ──► enc payload ──► ZW inject ──► GitHub README
                                                              │
                                                     poll (random order)
                                                              ▼
                                                           Agent
                                              ┌──────────────┼──────────────┐
                                              │              │              │
                                          ZW extract    heartbeat     persistence
                                              │         (ZW+redirect) (cron/autostart)
                                         decrypt+exec
                                              │
                                    ┌─────────┼─────────┐
                                    │         │         │
                                  shell   download    bind shell
                                                      (TCP/UDP/ICMP)
```

## Crate Dependency Graph

```
arcticfox-core ─────────────────────────────────────────────┐
    │                                                        │
    ├── arcticfox-agent ──┬── arcticfox-lol                  │
    │   (stealth,          │                                  │
    │    heartbeat,        ├── arcticfox-zwtransport ────────┤
    │    rustsploit_bridge)│                                  │
    │                      └── arcticfox-uring               │
    ├── arcticfox-api                                        │
    ├── arcticfox-control                                    │
    ├── arcticfox-scan                                       │
    ├── arcticfox-mcp ──── arcticfox-lol                     │
    └── arcticfox-bindshell ── arcticfox-zwtransport
```

## ZW Codec

Base-4 encoding using 4 invisible Unicode characters per byte:

| Char | Codepoint | Name | Value |
|---|---|---|---|
| `​` | U+200B | Zero Width Space | 0 |
| `‌` | U+200C | Zero Width Non-Joiner | 1 |
| `‍` | U+200D | Zero Width Joiner | 2 |
| `﻿` | U+FEFF | Zero Width No-Break Space | 3 |

Each input byte b produces 4 ZW chars: `ZW[b>>6&3] ZW[b>>4&3] ZW[b>>2&3] ZW[b&3]`.

Payload format: `START_MARKER(16) + ZW_ENCODED_DATA + END_MARKER(16) [+ optional 1MB padding]`

## AEAD Pipeline

```
SEND:  plaintext → ChaCha20-Poly1305 encrypt → ciphertext||tag(16B) → ZW encode → frame delimiters → socket
RECV:  socket → find frame → ZW decode → ciphertext||tag → ChaCha20-Poly1305 decrypt → plaintext
```

Key: 32 bytes. Nonce: 12 bytes (counter-based, sequential). Tag: 16 bytes.

## Agent Self-Healing

1. **Exponential backoff**: fail_count × base_interval, max 3600s
2. **Auto-deactivation**: after max_fails × 2 consecutive failures, repo marked inactive
3. **Dynamic repo discovery**: new repos learned from payload `gh`/`gl`/`dp` fields
4. **Watchdog respawn**: parent PID monitored every 5s, respawned under new name on death
5. **Multi-repo failover**: randomized polling order, skip dead repos during backoff

## Framing (ZW Transport)

16-char start/end delimiters (2¹⁶ = 4.3×10⁹ combinations).  
Frame: `FRAME_START(16) + ZW_ENCODED_AEAD_CIPHERTEXT + FRAME_END(16)`  
Max payload: 64 KiB. Buffer: 320 KiB.
