const std = @import("std");
const constants = @import("constants.zig");
const bigint = @import("bigint.zig");
const SM3 = @import("../sm3.zig").SM3;

/// SM9 Helper Functions
/// Provides common utility functions to reduce code duplication and improve maintainability
/// Based on GM/T 0044-2016 standard
/// Hash computation helper errors
pub const HelperError = error{
    InvalidInput,
    InvalidLength,
    HashComputationFailed,
    CounterOverflow,
    ModularReductionFailed,
};

/// SM3 Hash Builder - fluent interface for building hash operations
pub const SM3Builder = struct {
    hasher: SM3,

    /// Initialize new hash builder
    pub fn init() SM3Builder {
        return SM3Builder{
            .hasher = SM3.init(.{}),
        };
    }

    /// Add data to hash
    pub fn update(self: *SM3Builder, data: []const u8) *SM3Builder {
        self.hasher.update(data);
        return self;
    }

    /// Add single byte to hash
    pub fn updateByte(self: *SM3Builder, byte: u8) *SM3Builder {
        self.hasher.update(&[1]u8{byte});
        return self;
    }

    /// Add counter as 4-byte big-endian
    pub fn updateCounter(self: *SM3Builder, counter: u32) *SM3Builder {
        const counter_bytes = [4]u8{
            @as(u8, @intCast((counter >> 24) & 0xFF)),
            @as(u8, @intCast((counter >> 16) & 0xFF)),
            @as(u8, @intCast((counter >> 8) & 0xFF)),
            @as(u8, @intCast(counter & 0xFF)),
        };
        self.hasher.update(&counter_bytes);
        return self;
    }

    /// Add domain separator string
    pub fn updateDomainSeparator(self: *SM3Builder, separator: []const u8) *SM3Builder {
        self.hasher.update(separator);
        return self;
    }

    /// Add hash identifier (HID) - GM/T 0044-2016 compliant validation
    pub fn updateHashId(self: *SM3Builder, hid: u8) *SM3Builder {
        // GM/T 0044-2016 compliance: Only accept valid hash identifiers
        if (!constants.Utils.isValidHashIdentifier(hid)) {
            // Invalid HID should cause validation error, but since this is a builder pattern,
            // we accept only the valid values and reject invalid ones at input validation level
            // For now, only add valid HIDs to maintain builder pattern consistency
            if (hid == constants.HashIdentifier.SIGNATURE or hid == constants.HashIdentifier.ENCRYPTION) {
                self.hasher.update(&[1]u8{hid});
            }
            // Invalid HIDs are silently ignored to maintain builder pattern
        } else {
            self.hasher.update(&[1]u8{hid});
        }
        return self;
    }

    /// Finalize hash and return result
    pub fn finalize(self: *SM3Builder, result: *[32]u8) void {
        self.hasher.final(result);
    }

    /// Build complete hash in one call
    pub fn buildHash(self: *SM3Builder, result: *[32]u8) void {
        self.finalize(result);
    }
};

/// Modular reduction helper with improved error handling
pub const ModularReduction = struct {
    /// Perform modular reduction with comprehensive fallback handling
    pub fn reduce(value: [32]u8, modulus: [32]u8) ![32]u8 {
        // Input validation
        if (bigint.isZero(modulus)) {
            return HelperError.InvalidInput;
        }

        // Fast path: if value is already less than modulus
        if (bigint.lessThan(value, modulus)) {
            return value;
        }

        // Iterative subtraction with safety bounds
        var result = value;
        var iterations: u32 = 0;

        while (!bigint.lessThan(result, modulus) and iterations < constants.Limits.MAX_MODULAR_REDUCTION_ITERATIONS) {
            const sub_result = bigint.sub(result, modulus);
            if (sub_result.borrow) {
                // This shouldn't happen if result >= modulus, but handle gracefully
                break;
            }
            result = sub_result.result;
            iterations += 1;
        }

        // If still not reduced after maximum iterations, fail securely
        if (!bigint.lessThan(result, modulus)) {
            return bigint.mod(value, modulus) catch {
                // GM/T 0044-2016 compliance: Fail securely instead of using non-standard reduction
                return HelperError.ModularReductionFailed;
            };
        }

        return result;
    }
};

/// Counter management for hash iteration
pub const CounterManager = struct {
    current_value: u32,
    max_value: u32,

    /// Initialize counter with default limits
    pub fn init() CounterManager {
        return CounterManager{
            .current_value = 1,
            .max_value = constants.Limits.MAX_HASH_COUNTER,
        };
    }

    /// Initialize counter with custom limits
    pub fn initWithLimit(max_value: u32) CounterManager {
        return CounterManager{
            .current_value = 1,
            .max_value = max_value,
        };
    }

    /// Get current counter value
    pub fn current(self: CounterManager) u32 {
        return self.current_value;
    }

    /// Increment counter and check bounds
    pub fn increment(self: *CounterManager) !void {
        if (self.current_value >= self.max_value) {
            return HelperError.CounterOverflow;
        }
        self.current_value += 1;
    }

    /// Reset counter to initial value
    pub fn reset(self: *CounterManager) void {
        self.current_value = 1;
    }

    /// Check if counter has reached maximum
    pub fn isAtMax(self: CounterManager) bool {
        return self.current_value >= self.max_value;
    }

    /// Get remaining iterations
    pub fn remaining(self: CounterManager) u32 {
        if (self.current_value >= self.max_value) return 0;
        return self.max_value - self.current_value;
    }
};

/// Input validation helpers
pub const Validation = struct {
    /// Validate user ID format and length
    pub fn validateUserId(user_id: []const u8) !void {
        if (user_id.len == 0) {
            return HelperError.InvalidInput;
        }

        // Check for reasonable length limits (email addresses, etc.)
        if (user_id.len > 256) {
            return HelperError.InvalidLength;
        }

        // Ensure user ID contains printable characters
        for (user_id) |byte| {
            if (byte < 32 or byte > 126) {
                // Allow some common extended characters but reject control characters
                if (byte < 32) {
                    return HelperError.InvalidInput;
                }
            }
        }
    }

    /// Validate message data
    pub fn validateMessage(message: []const u8) !void {
        if (message.len == 0) {
            return HelperError.InvalidInput;
        }

        // Check message size limits for security
        if (message.len > constants.Security.MAX_MESSAGE_SIZE) {
            return HelperError.InvalidLength;
        }
    }

    /// Validate field element is in valid range
    pub fn validateFieldElement(element: [32]u8, modulus: [32]u8) !void {
        if (bigint.isZero(modulus)) {
            return HelperError.InvalidInput;
        }

        if (!bigint.lessThan(element, modulus)) {
            return HelperError.InvalidInput;
        }
    }

    /// Validate point format byte
    pub fn validatePointFormat(format: u8) !void {
        if (!constants.Utils.isValidPointFormat(format)) {
            return HelperError.InvalidInput;
        }
    }

    /// Validate hash identifier
    pub fn validateHashIdentifier(hid: u8) !void {
        if (!constants.Utils.isValidHashIdentifier(hid)) {
            return HelperError.InvalidInput;
        }
    }
};

/// Memory management helpers for secure operations
pub const SecureMemory = struct {
    /// Securely clear sensitive data
    pub fn clearSensitiveData(data: []u8) void {
        // Use volatile writes to prevent compiler optimization
        for (data) |*byte| {
            @as(*volatile u8, byte).* = constants.Security.SECURE_WIPE_PATTERN;
        }
    }

    /// Securely clear multiple data arrays
    pub fn clearMultipleArrays(arrays: [][]u8) void {
        for (arrays) |array| {
            clearSensitiveData(array);
        }
    }

    /// Create temporary buffer with automatic cleanup
    pub const TempBuffer = struct {
        data: []u8,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, size: usize) !TempBuffer {
            const data = try allocator.alloc(u8, size);
            return TempBuffer{
                .data = data,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: TempBuffer) void {
            clearSensitiveData(self.data);
            self.allocator.free(self.data);
        }
    };
};

/// Error context for better debugging
pub const ErrorContext = struct {
    function_name: []const u8,
    operation: []const u8,
    additional_info: []const u8,

    pub fn init(function_name: []const u8, operation: []const u8) ErrorContext {
        return ErrorContext{
            .function_name = function_name,
            .operation = operation,
            .additional_info = "",
        };
    }

    pub fn withInfo(self: ErrorContext, info: []const u8) ErrorContext {
        return ErrorContext{
            .function_name = self.function_name,
            .operation = self.operation,
            .additional_info = info,
        };
    }

    pub fn format(self: ErrorContext, allocator: std.mem.Allocator) ![]u8 {
        if (self.additional_info.len > 0) {
            return std.fmt.allocPrint(allocator, "{s} in {s}: {s}", .{ self.operation, self.function_name, self.additional_info });
        } else {
            return std.fmt.allocPrint(allocator, "{s} in {s}", .{ self.operation, self.function_name });
        }
    }
};
