# Sourced by the e2e scripts. In a git worktree the submodules are empty and
# target/ is a link into the main checkout, so point Docker at the main
# checkout's copies; in the main checkout these are just the local paths.
E2E_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$E2E_DIR/.." && pwd)
MAIN=$ROOT
if [ ! -e "$ROOT/third_party/ZeroTierOne/node" ]; then
  MAIN=$(cd "$(git -C "$ROOT" rev-parse --git-common-dir)/.." && pwd)
fi
export ZTNX_ZT_DIR=${ZTNX_ZT_DIR:-$MAIN/third_party/ZeroTierOne}
export ZTNX_OUT_DIR=${ZTNX_OUT_DIR:-$MAIN/target/linux}
export ZTNX_STATE_DIR=${ZTNX_STATE_DIR:-$MAIN/e2e/state}
mkdir -p "$ZTNX_OUT_DIR" "$ZTNX_STATE_DIR/controller" "$ZTNX_STATE_DIR/peer" "$ZTNX_STATE_DIR/peer2" "$ZTNX_STATE_DIR/client"
