#!/bin/bash
# test_repo.sh - Validates the repository structure and key files
# Usage: bash test_repo.sh

PASS=0
FAIL=0

check_exists() {
    local path="$1"
    local description="$2"
    if [ -e "$path" ]; then
        echo "[PASS] $description exists: $path"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $description missing: $path"
        FAIL=$((FAIL + 1))
    fi
}

check_not_empty() {
    local path="$1"
    local description="$2"
    if [ -s "$path" ]; then
        echo "[PASS] $description is not empty: $path"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $description is empty or missing: $path"
        FAIL=$((FAIL + 1))
    fi
}

echo "========================================"
echo "Repository Structure Test"
echo "========================================"
echo ""

# Core files
check_exists "sample.sh" "SSH brute force script"
check_exists "command.txt" "Command reference"
check_exists "Lesson6-File_Permission" "Lesson 6 file permissions resource"

# Malware analysis directory
check_exists "mal" "Malware analysis directory"
check_not_empty "mal/test.txt" "Malware test file"
check_exists "mal/MOCK_1_ANALYSIS.md" "Mock 1 analysis notes"
check_exists "mal/MOCK_1_DETAILED_IDA_ANALYSIS.md" "Mock 1 IDA analysis"
check_exists "mal/ReverseMe_Analysis.md" "ReverseMe analysis"
check_exists "mal/ST2617_MOCK_TEST_COMPLETE_GUIDE.md" "ST2617 mock test guide"
check_exists "mal/ADDRESS_DIFFERENCES_EXPLAINED.md" "Address differences doc"
check_exists "mal/RADARE2_FUNCTION_ADDRESSES.md" "Radare2 function addresses doc"

# Lab 6 part 2
check_exists "mal/lab6_part2" "Lab 6 part 2 directory"
check_exists "mal/lab6_part2/patching_tut.zip" "Patching tutorial archive"
check_exists "mal/lab6_part2/PatchMe.exe.zip" "PatchMe exercise archive"
check_exists "mal/lab6_part2/pe_scripts.zip" "PE scripts archive"

# Validate sample.sh has a shebang
if head -1 sample.sh | grep -q '^#!/bin/bash'; then
    echo "[PASS] sample.sh has correct shebang"
    PASS=$((PASS + 1))
else
    echo "[FAIL] sample.sh missing shebang"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "========================================"
echo "Results: $PASS passed, $FAIL failed"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
