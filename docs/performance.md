# SM9 Performance

Measured on 2026-11-13 with Zig 0.16.0, `ReleaseFast`, on:

- CPU: Intel Core i7-1068NG7 @ 2.30 GHz
- OS: macOS x86_64
- RAM: 16 GiB

Command:

```bash
zig build bench -Doptimize=ReleaseFast -- --filter SM9
```

Results:

| Operation | Time |
|---|---:|
| SM9 pairing `e(P1, P2)` | 1.151 s |
| SM9 key extraction | 7.579 ms |
| SM9 sign | 1.182 s |
| SM9 verify | 2.227 s |
| SM9 encrypt (32 B) | 1.109 s |
| SM9 decrypt (32 B) | 1.113 s |

Each sign/verify/encrypt/decrypt operation includes one or two full R-ate
pairings, so the pairing cost dominates. zbench reports a single run for these
operations because one run already exceeds the default time budget.

The field inverse was changed from Fermat exponentiation (`a^(p-2)`) to a binary
extended Euclidean inverse. That reduced key extraction from roughly 330 ms to
about 7.6 ms. Further gains require a Montgomery/Barrett field multiplier and a
projective/sparse pairing implementation; those are tracked in
[ROADMAP.md](../ROADMAP.md).

These numbers are for this machine and this commit only. They are not a
comparison against GmSSL or another SM9 implementation.
