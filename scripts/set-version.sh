#!/bin/sh
# Stamp a release version into every place that carries one. Used by the release workflow and PKGBUILD,
# so the git tag (vX.Y.Z) is the only thing that has to be changed to release.
set -eu
v="${1#v}"
printf '%s\n' "$v" | grep -Eq '^[0-9]+(\.[0-9]+){1,3}$' || { echo "invalid version: $1" >&2; exit 1; }
sed -i "s/^__version__ = \".*\"/__version__ = \"$v\"/" src/cachy_sec/__init__.py
sed -i "s/^version = \".*\"/version = \"$v\"/" pyproject.toml
[ ! -f PKGBUILD ] || sed -i "s/^pkgver=.*/pkgver=$v/" PKGBUILD
grep -q "^__version__ = \"$v\"" src/cachy_sec/__init__.py
grep -q "^version = \"$v\"" pyproject.toml
echo "$v"
