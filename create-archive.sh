#!/bin/bash

#
# create-archive.sh
# Creates a clean archive of the soft-enclave project
# Excludes node_modules, build artifacts, and other bloat
#

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Creating soft-enclave.zip archive...${NC}"

# Output file
ARCHIVE_NAME="soft-enclave.zip"

# Remove old archive if it exists
if [ -f "$ARCHIVE_NAME" ]; then
    echo "Removing old archive..."
    rm "$ARCHIVE_NAME"
fi

# Create archive with exclusions
echo "Archiving files..."
zip -r "$ARCHIVE_NAME" . \
    -x "*.git*" \
    -x "time-stuff.mkv" \
    -x "*node_modules/*" \
    -x "*dist/*" \
    -x "*build/*" \
    -x "*.DS_Store" \
    -x "*__pycache__/*" \
    -x "*.pyc" \
    -x "*coverage/*" \
    -x "*.log" \
    -x "*tmp/*" \
    -x "*temp/*" \
    -x "*.cache/*" \
    -x "*.zip" \
    -x "*.idea/*" \
    -x "*.vscode/*" \
    -x "*.swp" \
    -x "*.swo" \
    -x "*~" \
    -x "*.env" \
    -x "*.env.local" \
    -x "*package-lock.json" \
    -x "*yarn.lock" \
    -x "*pnpm-lock.yaml" \
    -x "*computation/*" \
    -x "*media/*"

# Get archive size
SIZE=$(du -h "$ARCHIVE_NAME" | cut -f1)

echo ""
echo -e "${GREEN}✓ Archive created successfully!${NC}"
echo -e "${BLUE}File: ${NC}$ARCHIVE_NAME"
echo -e "${BLUE}Size: ${NC}$SIZE"
echo ""

# List contents for verification
echo "Archive contents:"
echo "---"
unzip -l "$ARCHIVE_NAME" | head -n 30
echo "..."
echo ""
echo "Total files:"
unzip -l "$ARCHIVE_NAME" | tail -n 1
echo ""

echo -e "${GREEN}Done!${NC}"
