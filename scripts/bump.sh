#!/usr/bin/env bash
# Ручной bump VERSION (patch|minor|major). Тег и релиз всё равно создаёт CI
# при пуше в master — этот скрипт только меняет число и коммитит его.
set -euo pipefail
kind="${1:-patch}"
cd "$(dirname "$0")/.."

IFS=. read -r major minor patch < VERSION
case "$kind" in
  patch) patch=$((patch + 1)) ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  major) major=$((major + 1)); minor=0; patch=0 ;;
  *) echo "usage: $0 patch|minor|major" >&2; exit 2 ;;
esac

printf '%s.%s.%s\n' "$major" "$minor" "$patch" > VERSION
git commit -q -m "chore(release): v$(cat VERSION)" VERSION
echo "VERSION -> $(cat VERSION)"
