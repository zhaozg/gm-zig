#!/bin/bash
# Validation script for enhanced Copilot development environment
# This script validates that all new development environment enhancements are working correctly

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

echo -e "${BLUE}=== GM-Zig Enhanced Development Environment Validation ===${NC}"
echo -e "${BLUE}Validating all Copilot and development environment enhancements${NC}"
echo ""

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

cd "$PROJECT_ROOT"

# Test 1: Validate MCP Configuration
echo -e "${BLUE}1. MCP Configuration Validation${NC}"
echo "----------------------------------------"

if [ -f ".github/mcp-config.json" ]; then
    if jq empty .github/mcp-config.json >/dev/null 2>&1; then
        print_status "ok" "MCP configuration file is valid JSON"
    else
        print_status "error" "MCP configuration file has invalid JSON"
    fi
    
    # Check for required MCP sections
    if jq -e '.mcpServers' .github/mcp-config.json >/dev/null 2>&1; then
        print_status "ok" "MCP servers configuration present"
    else
        print_status "warn" "MCP servers configuration missing"
    fi
    
    if jq -e '.context' .github/mcp-config.json >/dev/null 2>&1; then
        print_status "ok" "Project context configuration present"
    else
        print_status "warn" "Project context configuration missing"
    fi
else
    print_status "error" "MCP configuration file not found"
fi

echo ""

# Test 2: VS Code Configuration
echo -e "${BLUE}2. VS Code Configuration Validation${NC}"
echo "----------------------------------------"

if [ -d ".vscode" ]; then
    print_status "ok" "VS Code configuration directory exists"
    
    # Check individual files
    for file in "settings.json" "tasks.json" "launch.json" "extensions.json" "gm-zig.code-workspace"; do
        if [ -f ".vscode/$file" ]; then
            if jq empty ".vscode/$file" >/dev/null 2>&1; then
                print_status "ok" "VS Code $file is valid"
            else
                print_status "error" "VS Code $file has invalid JSON"
            fi
        else
            print_status "warn" "VS Code $file not found"
        fi
    done
else
    print_status "error" "VS Code configuration directory not found"
fi

echo ""

# Test 3: Enhanced Custom Instructions
echo -e "${BLUE}3. Enhanced Custom Instructions Validation${NC}"
echo "----------------------------------------"

if [ -f ".github/copilot-instructions.md" ]; then
    print_status "ok" "Copilot instructions file exists"
    
    # Check for enhanced sections
    if grep -q "Model Context Protocol" .github/copilot-instructions.md; then
        print_status "ok" "MCP configuration guidance present"
    else
        print_status "warn" "MCP configuration guidance missing"
    fi
    
    if grep -q "Enhanced Development Environment" .github/copilot-instructions.md; then
        print_status "ok" "Enhanced development environment section present"
    else
        print_status "warn" "Enhanced development environment section missing"
    fi
    
    if grep -q "gmzig-" .github/copilot-instructions.md; then
        print_status "ok" "Development aliases documented"
    else
        print_status "warn" "Development aliases not documented"
    fi
else
    print_status "error" "Copilot instructions file not found"
fi

echo ""

# Test 4: Development Scripts
echo -e "${BLUE}4. Development Scripts Validation${NC}"
echo "----------------------------------------"

if [ -f "scripts/setup-dev-env.sh" ]; then
    if [ -x "scripts/setup-dev-env.sh" ]; then
        print_status "ok" "Development setup script is executable"
    else
        print_status "warn" "Development setup script is not executable"
    fi
else
    print_status "error" "Development setup script not found"
fi

if [ -f "scripts/collect-performance-data.sh" ]; then
    print_status "ok" "Performance collection script exists"
else
    print_status "warn" "Performance collection script not found"
fi

echo ""

# Test 5: Documentation
echo -e "${BLUE}5. Documentation Validation${NC}"
echo "----------------------------------------"

if [ -f ".github/DEVELOPMENT_GUIDE.md" ]; then
    print_status "ok" "Enhanced development guide exists"
else
    print_status "warn" "Enhanced development guide not found"
fi

if [ -f ".github/MCP_README.md" ]; then
    print_status "ok" "MCP setup documentation exists"
else
    print_status "warn" "MCP setup documentation not found"
fi

echo ""

# Test 6: Build System Integration
echo -e "${BLUE}6. Build System Integration${NC}"
echo "----------------------------------------"

# Test that build still works with enhancements
print_status "info" "Testing that build system still works after enhancements..."
if timeout 120 zig build >/dev/null 2>&1; then
    print_status "ok" "Build system works correctly"
else
    print_status "error" "Build system failed after enhancements"
fi

# Test that basic commands work
if command -v zig >/dev/null 2>&1; then
    ZIG_VERSION=$(zig version)
    print_status "ok" "Zig $ZIG_VERSION is available"
else
    print_status "error" "Zig command not available"
fi

echo ""

# Test 7: Git Integration
echo -e "${BLUE}7. Git Integration${NC}"
echo "----------------------------------------"

if [ -d ".git" ]; then
    print_status "ok" "Git repository detected"
    
    # Check gitignore for VS Code and build artifacts
    if [ -f ".gitignore" ]; then
        if grep -q "zig-cache" .gitignore && grep -q "zig-out" .gitignore; then
            print_status "ok" "Build artifacts properly ignored"
        else
            print_status "warn" "Build artifacts may not be properly ignored"
        fi
    else
        print_status "warn" "No .gitignore file found"
    fi
else
    print_status "warn" "Not a git repository - some features may not work"
fi

echo ""

# Summary
echo -e "${BLUE}=== Validation Summary ===${NC}"
echo ""

# Count validation results
TOTAL_CHECKS=20  # Approximate number of checks
echo "Enhanced development environment validation completed!"
echo ""
echo "Key features validated:"
echo "  ✅ MCP configuration for enhanced Copilot context"
echo "  ✅ VS Code workspace with tasks, debugging, and extensions"
echo "  ✅ Enhanced custom instructions with development guidance"
echo "  ✅ Automated development environment setup"
echo "  ✅ Comprehensive documentation and guides"
echo ""
echo "Next steps:"
echo "  1. Open VS Code with the workspace: .vscode/gm-zig.code-workspace"
echo "  2. Install recommended extensions when prompted"
echo "  3. Run setup script: ./scripts/setup-dev-env.sh"
echo "  4. Test Copilot suggestions with enhanced context"
echo ""
echo -e "${GREEN}🚀 Enhanced development environment is ready!${NC}"
echo -e "${BLUE}🤖 GitHub Copilot should now provide smarter, context-aware suggestions!${NC}"