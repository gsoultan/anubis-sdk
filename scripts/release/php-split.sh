#!/usr/bin/env bash
#
# Publish the PHP package by splitting php/ into a read-only mirror.
#
#   scripts/release/php-split.sh v0.1.0          split, verify, push nothing
#   scripts/release/php-split.sh v0.1.0 --push   and publish the mirror
#
# Packagist reads composer.json from a repository root, and this repository
# keeps it in php/. There is no way to point it at a subdirectory, so a
# monorepo publishes to Packagist the way Symfony does: from a derived
# repository containing only that subtree.
#
# composer.json's psr-4 map is already relative to php/, so nothing inside it
# changes when the subtree becomes a root. That is why this is a split and not
# a rewrite.
#
# The mirror is derived and never edited. Anything committed to it directly is
# lost at the next split.
set -euo pipefail

TAG=${1:-}
[ -n "$TAG" ] || { echo "usage: $0 <tag|ref> [--push]" >&2; exit 2; }
PUSH=${2:-}
MIRROR=${ANUBIS_PHP_MIRROR:-https://github.com/gsoultan/anubis-sdk-php.git}

cd "$(dirname "$0")/../.."

git rev-parse -q --verify "$TAG^{commit}" >/dev/null ||
  { echo "no such tag or ref: $TAG" >&2; exit 1; }

echo "splitting php/ out of $TAG"
sha=$(git subtree split --prefix=php "$TAG")
echo "  split commit  $sha"

# The whole point of the exercise, so it is asserted rather than assumed.
git cat-file -e "$sha:composer.json" 2>/dev/null ||
  { echo "::error:: split tree has no composer.json at its root" >&2; exit 1; }

# A mirror published without these is a package page with no text and no
# licence, which is how both get noticed a week after the release.
for f in README.md LICENSE; do
  git cat-file -e "$sha:$f" 2>/dev/null ||
    { echo "::error:: split tree is missing $f" >&2; exit 1; }
done

echo "  root contents"
git ls-tree --name-only "$sha" | sed 's/^/    /'

if [ "$PUSH" != "--push" ]; then
  echo
  echo "nothing pushed. re-run with --push to publish $TAG to"
  echo "  $MIRROR"
  exit 0
fi

git push "$MIRROR" "$sha:refs/heads/main" --force
git push "$MIRROR" "$sha:refs/tags/$TAG"
echo "published $TAG to $MIRROR"
