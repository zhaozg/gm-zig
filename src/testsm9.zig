// SM9 Test Suite - Consolidated into src/test.zig
//
// All SM9 tests have been moved to src/test.zig for unified test management.
// Please use `zig test src/test.zig` to run all tests including the complete SM9 test suite.
//
// This file is maintained for compatibility and redirects to the main test suite.

test {
    // Redirect to main test suite that includes all SM9 tests
    _ = @import("test.zig");
}
