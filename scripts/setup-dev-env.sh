#!/bin/bash
# Development Environment Setup Script for GM-Zig
# This script helps set up a complete development environment for the GM-Zig cryptographic library

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ZIG_VERSION="0.15.1"

echo -e "${BLUE}=== GM-Zig Development Environment Setup ===${NC}"
echo -e "${BLUE}Setting up development environment for the GM-Zig cryptographic library${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" == "ok" ]; then
        echo -e "${GREEN}✅ $message${NC}"
    elif [ "$status" == "warn" ]; then
        echo -e "${YELLOW}⚠️  $message${NC}"
    elif [ "$status" == "error" ]; then
        echo -e "${RED}❌ $message${NC}"
    else
        echo -e "${BLUE}ℹ️  $message${NC}"
    fi
}

# Check system requirements
echo -e "${BLUE}1. Checking System Requirements${NC}"
echo "----------------------------------------"

# Check for required tools
if command_exists zig; then
    CURRENT_ZIG=$(zig version)
    if [[ "$CURRENT_ZIG" == "0.14."* ]] || [[ "$CURRENT_ZIG" == "0.15."* ]]; then
        print_status "ok" "Zig $CURRENT_ZIG is installed (compatible)"
    else
        print_status "warn" "Zig $CURRENT_ZIG detected - may have compatibility issues"
        print_status "info" "Recommended version: 0.14.1+ or 0.15.x"
    fi
else
    print_status "error" "Zig not found - installing Zig $ZIG_VERSION"
    
    # Download and install Zig
    cd /tmp
    wget "https://ziglang.org/download/$ZIG_VERSION/zig-linux-x86_64-$ZIG_VERSION.tar.xz" -O "zig-$ZIG_VERSION.tar.xz"
    tar -xf "zig-$ZIG_VERSION.tar.xz"
    sudo mv "zig-linux-x86_64-$ZIG_VERSION" /usr/local/zig
    sudo ln -sf /usr/local/zig/zig /usr/local/bin/zig
    
    if command_exists zig; then
        print_status "ok" "Zig $ZIG_VERSION installed successfully"
    else
        print_status "error" "Failed to install Zig"
        exit 1
    fi
fi

# Check for Git
if command_exists git; then
    print_status "ok" "Git is available"
else
    print_status "error" "Git is required but not installed"
    exit 1
fi

# Check for optional tools
if command_exists jq; then
    print_status "ok" "jq is available (for JSON processing)"
else
    print_status "warn" "jq not found - installing for performance data processing"
    sudo apt-get update && sudo apt-get install -y jq
fi

if command_exists gdb; then
    print_status "ok" "GDB is available (for debugging)"
else
    print_status "warn" "GDB not found - debugging capabilities limited"
fi

echo ""

# Verify project build
echo -e "${BLUE}2. Verifying Project Build${NC}"
echo "----------------------------------------"

cd "$PROJECT_ROOT"

# Check build.zig.zon for enum literal issue
if grep -q '\.name = "gmlib"' build.zig.zon; then
    print_status "warn" "Fixing build.zig.zon enum literal issue"
    sed -i 's/\.name = "gmlib"/\.name = .gmlib/' build.zig.zon
    print_status "ok" "Fixed build.zig.zon enum literal format"
fi

# Test build
print_status "info" "Testing project build (this may take 15-30 seconds)..."
if timeout 300 zig build >/dev/null 2>&1; then
    print_status "ok" "Project builds successfully"
else
    print_status "error" "Project build failed"
    echo "Try running: zig build"
    exit 1
fi

# Test optimized build
print_status "info" "Testing optimized build..."
if timeout 300 zig build -Doptimize=ReleaseFast >/dev/null 2>&1; then
    print_status "ok" "Optimized build successful"
else
    print_status "warn" "Optimized build failed - debug builds still work"
fi

echo ""

# Setup development tools
echo -e "${BLUE}3. Setting Up Development Tools${NC}"
echo "----------------------------------------"

# Create useful aliases
ALIAS_FILE="$HOME/.gm_zig_aliases"
cat > "$ALIAS_FILE" << 'EOF'
# GM-Zig Development Aliases
alias gmzig-build='zig build'
alias gmzig-build-fast='zig build -Doptimize=ReleaseFast'
alias gmzig-test='zig build test'
alias gmzig-run='zig build run'
alias gmzig-fmt='zig fmt build.zig src/'
alias gmzig-fmt-check='zig fmt --check build.zig src/'
alias gmzig-clean='rm -rf zig-cache zig-out'
alias gmzig-perf='./scripts/collect-performance-data.sh'
alias gmzig-validate='zig build && zig build -Doptimize=ReleaseFast && zig build test'
EOF

print_status "ok" "Created development aliases in $ALIAS_FILE"
print_status "info" "Add 'source $ALIAS_FILE' to your shell profile to use aliases"

# Setup git hooks (optional)
if [ -d "$PROJECT_ROOT/.git" ]; then
    HOOKS_DIR="$PROJECT_ROOT/.git/hooks"
    
    # Pre-commit hook for formatting
    cat > "$HOOKS_DIR/pre-commit" << 'EOF'
#!/bin/bash
# GM-Zig pre-commit hook - check code formatting
echo "Running code format check..."
if ! zig fmt --check build.zig src/ >/dev/null 2>&1; then
    echo "❌ Code formatting check failed!"
    echo "Run 'zig fmt build.zig src/' to fix formatting issues"
    exit 1
fi
echo "✅ Code formatting check passed"
EOF
    chmod +x "$HOOKS_DIR/pre-commit"
    print_status "ok" "Installed git pre-commit hook for formatting checks"
fi

echo ""

# Performance baseline
echo -e "${BLUE}4. Establishing Performance Baseline${NC}"
echo "----------------------------------------"

if [ -x "$PROJECT_ROOT/scripts/collect-performance-data.sh" ]; then
    print_status "info" "Running performance baseline (this may take 30-60 seconds)..."
    if timeout 120 "$PROJECT_ROOT/scripts/collect-performance-data.sh" >/dev/null 2>&1; then
        print_status "ok" "Performance baseline established"
    else
        print_status "warn" "Performance baseline failed - not critical for development"
    fi
else
    print_status "warn" "Performance script not found - skipping baseline"
fi

echo ""

# Final validation
echo -e "${BLUE}5. Final Validation${NC}"
echo "----------------------------------------"

# Run a quick demo
print_status "info" "Running quick demo validation..."
if timeout 60 zig build run >/dev/null 2>&1; then
    print_status "ok" "Demo runs successfully"
else
    print_status "warn" "Demo failed to run - check build issues"
fi

# Check code formatting
print_status "info" "Checking code formatting..."
if zig fmt --check build.zig src/ >/dev/null 2>&1; then
    print_status "ok" "Code formatting is correct"
else
    print_status "warn" "Code formatting issues found - run 'zig fmt build.zig src/' to fix"
fi

echo ""
echo -e "${GREEN}=== Setup Complete! ===${NC}"
echo ""
echo "🚀 GM-Zig development environment is ready!"
echo ""
echo "Quick start commands:"
echo "  gmzig-build         # Build the library"
echo "  gmzig-test          # Run all tests"
echo "  gmzig-run           # Run demo"
echo "  gmzig-validate      # Full validation"
echo ""
echo "For VS Code users:"
echo "  - Open .vscode/gm-zig.code-workspace for full IDE integration"
echo "  - Install recommended extensions"
echo "  - Use Ctrl+Shift+P -> Tasks to access build tasks"
echo ""
echo "Next steps:"
echo "  1. Read README.md for project overview"
echo "  2. Check .github/copilot-instructions.md for detailed guidance"
echo "  3. Run 'gmzig-validate' to ensure everything works"
echo ""
echo -e "${BLUE}Happy coding with GM-Zig! 🔐${NC}"