# AGENT.md

## Build/Lint/Test Commands

- `zig build` - Compile zig source code to zig-out/bin/
- `zig build test --summary all` - Run All units test
- `zig fmt --check src` - Run code style check

## requirements

- Must build and test pass with Zig 0.16.x and 0.17.x (see `minimum_zig_version` in build.zig.zon), download URL in https://ziglang.org/download/index.json
- All CI must pass.
- Push PR after `zig fmt src`
