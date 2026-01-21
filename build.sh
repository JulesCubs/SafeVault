#!/bin/bash
# Script de compilación y publicación para SafeVault

set -e

echo "================================"
echo "SafeVault - Build & Publish Script"
echo "================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Variables
PROJECT_DIR="."
BUILD_CONFIG="${1:-Release}"
OUTPUT_DIR="./bin/publish"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo -e "${YELLOW}[INFO]${NC} Build Configuration: $BUILD_CONFIG"
echo -e "${YELLOW}[INFO]${NC} Output Directory: $OUTPUT_DIR"
echo ""

# Step 1: Clean
echo -e "${YELLOW}[1/5]${NC} Cleaning previous builds..."
dotnet clean --configuration $BUILD_CONFIG > /dev/null 2>&1 || true
rm -rf $OUTPUT_DIR || true
echo -e "${GREEN}✓${NC} Clean completed"
echo ""

# Step 2: Restore
echo -e "${YELLOW}[2/5]${NC} Restoring NuGet packages..."
dotnet restore $PROJECT_DIR
echo -e "${GREEN}✓${NC} Restore completed"
echo ""

# Step 3: Build
echo -e "${YELLOW}[3/5]${NC} Building project..."
dotnet build --configuration $BUILD_CONFIG --no-restore
echo -e "${GREEN}✓${NC} Build completed"
echo ""

# Step 4: Test
echo -e "${YELLOW}[4/5]${NC} Running tests..."
dotnet test --configuration $BUILD_CONFIG --no-build --verbosity minimal || {
    echo -e "${RED}✗${NC} Tests failed!"
    exit 1
}
echo -e "${GREEN}✓${NC} Tests passed"
echo ""

# Step 5: Publish
echo -e "${YELLOW}[5/5]${NC} Publishing application..."
dotnet publish --configuration $BUILD_CONFIG \
    --no-build \
    --output $OUTPUT_DIR \
    --self-contained true \
    --runtime linux-x64
echo -e "${GREEN}✓${NC} Publish completed"
echo ""

# Summary
echo "================================"
echo -e "${GREEN}BUILD SUCCESSFUL${NC}"
echo "================================"
echo ""
echo "Output location: $OUTPUT_DIR"
echo ""
echo "To run the application:"
echo "  cd $OUTPUT_DIR"
echo "  ./SafeVault"
echo ""
echo "Or using dotnet:"
echo "  dotnet $OUTPUT_DIR/SafeVault.dll"
echo ""
