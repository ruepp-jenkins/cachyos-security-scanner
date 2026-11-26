#!/bin/sh
# Stamp a release version into every place that carries one. Used by the release workflow and PKGBUILD,
# so the git tag (vX.Y.Z) is the only thing that has to be changed to release.
set -eu
v="${1#v}"
printf '%s\n' "$v" | grep -Eq '^[0-9]+(\.[0-9]+){1,3}$' || { echo "invalid version: $1" >&2; exit 1; }
sed -i "s/^__version__ = \".*\"/__version__ = \"$v\"/" src/cachy_sec/__init__.py
sed -i "s/^version = \".*\"/version = \"$v\"/" pyproject.toml
[ ! -f PKGBUILD ] || sed -i "s/^pkgver=.*/pkgver=$v/" PKGBUILD
# the commit being released, for the About window (optional: left empty if it cannot be determined)
c=""
[ ! -e .git ] || c="$(git rev-parse HEAD 2>/dev/null || true)"
c="${c:-${GITHUB_SHA:-}}"
if printf '%s\n' "$c" | grep -Eq '^[0-9a-f]{40}$'; then
  sed -i "s/^__commit__ = \"[0-9a-f]*\"/__commit__ = \"$c\"/" src/cachy_sec/__init__.py
fi
grep -q "^__version__ = \"$v\"" src/cachy_sec/__init__.py
grep -q "^version = \"$v\"" pyproject.toml
echo "$v"
