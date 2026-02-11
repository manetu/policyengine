#!/usr/bin/env bash
#
# Run PolicyEngine Python integration tests
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo -e "${GREEN}PolicyEngine Test Runner${NC}"
echo "================================"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 is not installed${NC}"
    exit 1
fi

# Check if virtual environment exists, create if not
VENV_DIR="${PROJECT_ROOT}/.venv-test"
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source "${VENV_DIR}/bin/activate"

# Install/upgrade dependencies
echo -e "${YELLOW}Installing test dependencies...${NC}"
pip install -q --upgrade pip
pip install -q -r "${PROJECT_ROOT}/requirements-test.txt"

# Build the mpe binary if it doesn't exist
if [ ! -f "${PROJECT_ROOT}/target/mpe" ]; then
    echo -e "${YELLOW}Building mpe binary...${NC}"
    cd "$PROJECT_ROOT"
    make build
fi

# Parse arguments
PYTEST_ARGS=()
RUN_INTEGRATION=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --integration|-i)
            RUN_INTEGRATION=true
            shift
            ;;
        --smoke|-s)
            PYTEST_ARGS+=("-m" "smoke")
            shift
            ;;
        --coverage|-c)
            PYTEST_ARGS+=("--cov=tests" "--cov-report=html" "--cov-report=term")
            shift
            ;;
        *)
            PYTEST_ARGS+=("$1")
            shift
            ;;
    esac
done

# Default: skip integration tests unless explicitly requested
if [ "$RUN_INTEGRATION" = false ]; then
    PYTEST_ARGS+=("-m" "not integration")
fi

# Run pytest
echo -e "${GREEN}Running tests...${NC}"
echo "Command: pytest ${PYTEST_ARGS[*]}"
echo ""

cd "$PROJECT_ROOT"
pytest "${PYTEST_ARGS[@]}"
TEST_EXIT_CODE=$?

# Deactivate virtual environment
deactivate

# Print results
echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
else
    echo -e "${RED}❌ Tests failed with exit code ${TEST_EXIT_CODE}${NC}"
fi

exit $TEST_EXIT_CODE
