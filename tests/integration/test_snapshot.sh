#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT_DIR/baseline-guard"
TMP_DIR="$(mktemp -d /tmp/baseline-guard-snapshot-test.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/root/sub" "$TMP_DIR/root/excluded"
printf 'one\n' > "$TMP_DIR/root/a.txt"
printf 'two\n' > "$TMP_DIR/root/sub/b.txt"
printf 'skip\n' > "$TMP_DIR/root/excluded/c.txt"
printf 'direct\n' > "$TMP_DIR/root/direct.txt"
printf 'nested\n' > "$TMP_DIR/root/sub/nested.txt"
DB="$TMP_DIR/baseline.sqlite"

"$BIN" baseline snapshot --db "$DB" --label initial \
    --exclude "$TMP_DIR/root/excluded" "$TMP_DIR/root"

python3 - "$DB" <<'PY'
import sqlite3
import sys

con = sqlite3.connect(sys.argv[1])
entries = con.execute("SELECT file_path FROM baseline_entries ORDER BY file_path").fetchall()
assert len(entries) == 4, entries
assert not any("/excluded/" in row[0] for row in entries), entries
audit = con.execute("SELECT change_type, COUNT(*) FROM baseline_audit GROUP BY change_type").fetchall()
assert dict(audit) == {"added": 4}, audit
PY

"$BIN" baseline snapshot --db "$DB" --label second --no-recurse "$TMP_DIR/root"
python3 - "$DB" "$TMP_DIR" <<'PY'
import sqlite3
import sys

con = sqlite3.connect(sys.argv[1])
root = sys.argv[2] + "/root"
paths = [row[0] for row in con.execute(
    "SELECT file_path FROM baseline_entries WHERE file_path LIKE ? ORDER BY file_path",
    (root + "/%",),
)]
assert paths == [
    root + "/a.txt",
    root + "/direct.txt",
    root + "/sub/b.txt",
    root + "/sub/nested.txt",
], paths
PY

printf 'changed\n' > "$TMP_DIR/root/a.txt"
rm "$TMP_DIR/root/direct.txt"
"$BIN" baseline snapshot --db "$DB" --label third --no-recurse "$TMP_DIR/root"

python3 - "$DB" "$TMP_DIR" <<'PY'
import sqlite3
import sys

con = sqlite3.connect(sys.argv[1])
root = sys.argv[2] + "/root"
changes = con.execute(
    "SELECT change_type, file_path FROM baseline_audit WHERE snapshot_id = "
    "(SELECT snapshot_id FROM baseline_snapshots WHERE label = 'third') ORDER BY file_path"
).fetchall()
assert changes == [("modified", root + "/a.txt"), ("removed", root + "/direct.txt")], changes
PY

echo "test_baseline_snapshot: all tests passed"
