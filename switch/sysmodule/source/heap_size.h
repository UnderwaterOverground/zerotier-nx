// The sysmodule's heap size, written by tools/footprint.sh (make sysmodule):
// it fills the sysmodule's memory up to exactly 4 MB (4096 KB) with the
// code as built. Commit it with the code change that moved it.
#define ZTNX_HEAP_SIZE 0x1F9000
