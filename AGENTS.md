# AGENT.md

## Build/Lint/Test Commands

- `zig build` - Compile zig source code to zig-out/bin/
- `zig build test` - Run All units test
- `zig fmt --check src` - Run code style check

## requirements

- Must build and test pass with zig 0.14.x and 0.15.x, download URL in https://ziglang.org/download/index.json
- All CI must pass.
- Push PR after `zig fmt src`
