#!/bin/sh
# Applies patches/zerotier-*.patch, in order, to the ZeroTier submodule's
# working tree. Later patches build on earlier ones, so they can't be checked
# or applied one by one: whenever the set of patches changes, the tree is put
# back to the pinned commit and the whole series applied again. The
# submodule's own commit is never touched.
set -eu
cd "$(dirname "$0")/.."
zt=third_party/ZeroTierOne
stamp=target/zerotier-patches.stamp
if [ ! -e "$zt/.git" ]; then
  echo "$zt is not checked out here (a worktree?): not patching"
  exit 0
fi
want=$(cat patches/zerotier-*.patch | shasum | cut -d' ' -f1)
if [ "$(cat "$stamp" 2>/dev/null || true)" = "$want" ]; then
  exit 0
fi
git -C "$zt" checkout -- .
n=0
for p in patches/zerotier-*.patch; do
  git -C "$zt" apply "../../$p"
  n=$((n + 1))
done
mkdir -p target
echo "$want" > "$stamp"
echo "applied $n ZeroTier patches"
