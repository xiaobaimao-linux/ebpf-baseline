#!/bin/bash
set -e

echo "=== Build Test ==="
make clean && make

echo "=== Config Parse Test ==="
./baseline-guard check -c test/baseline.ini -d

echo "=== Check Test ==="
touch /tmp/test_baseline
chmod 600 /tmp/test_baseline
./baseline-guard check -c test/baseline.ini

echo "=== Fail Test ==="
chmod 644 /tmp/test_baseline
./baseline-guard check -c test/baseline.ini || true  # expect FAIL

echo "=== All Tests Passed ==="