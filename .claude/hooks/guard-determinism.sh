#!/usr/bin/env bash
# PreToolUse guard: flag HashMap iteration in builder/ingest code, where
# iteration order leaking into on-disk output breaks snapshot determinism.

INPUT="$(cat)"
FILE_PATH="$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')"
CONTENT="$(echo "$INPUT" | jq -r '.tool_input.content // .tool_input.new_string // empty')"

VIOLATIONS=""

if [[ "$FILE_PATH" =~ crates/vulngraph-data/src/(builder|ingest/|commands/build) ]]; then
  if echo "$CONTENT" | grep -qP 'HashMap.*\.iter\(\)|HashMap.*\.keys\(\)|HashMap.*\.values\(\)'; then
    VIOLATIONS="DETERMINISM: HashMap iteration in builder/ingest code. If output depends on iteration order, use BTreeMap or sort the result. Identical sources must produce byte-identical builds (snapshot_id). "
  fi
fi

if [ -n "$VIOLATIONS" ]; then
  jq -n --arg ctx "$VIOLATIONS" '{
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "defer",
      "additionalContext": ("INVARIANT WARNING: " + $ctx + "See CLAUDE.md Build Determinism.")
    }
  }'
else
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"defer"}}'
fi
