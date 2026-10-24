#!/bin/sh
# Verify that a built binary is a statically linked ELF for the expected machine.
#
#   scripts/check-elf.sh <file> <machine-substring> [mips-abi] [cpu-arch]
#
# Example:
#   scripts/check-elf.sh zig-out/bin/anytls-zig "MIPS32 rel2"
#   scripts/check-elf.sh zig-out/bin/anytls-zig "ARM, EABI5" "" v5TE
#   scripts/check-elf.sh zig-out/bin/anytls-zig AArch64

set -eu

file_path=${1:?usage: check-elf.sh <file> <machine-substring> [mips-abi]}
machine=${2:?usage: check-elf.sh <file> <machine-substring> [mips-abi]}
kind=${3:-}
cpu_arch=${4:-}

if [ ! -f "$file_path" ]; then
	echo "missing file: $file_path" >&2
	exit 1
fi

info=$(file -b "$file_path")
echo "$info"

case "$info" in
*"statically linked"*) ;;
*)
	echo "FAIL: not statically linked" >&2
	exit 1
	;;
esac

case "$info" in
*"$machine"*) ;;
*)
	echo "FAIL: expected machine '$machine'" >&2
	exit 1
	;;
esac

if ! readelf -d "$file_path" 2>&1 | grep -q "no dynamic section"; then
	echo "FAIL: dynamic section present" >&2
	exit 1
fi

if [ "$kind" = "mips" ]; then
	readelf -h "$file_path" | grep -q "o32" || {
		echo "FAIL: MIPS ABI is not o32" >&2
		exit 1
	}
	readelf -A "$file_path" | grep -q "Soft float" || {
		echo "FAIL: MIPS float ABI is not soft-float" >&2
		exit 1
	}
fi

if [ -n "$cpu_arch" ]; then
	readelf -A "$file_path" | grep -q "Tag_CPU_arch: $cpu_arch" || {
		echo "FAIL: expected CPU arch $cpu_arch" >&2
		exit 1
	}
fi

echo "OK: static $machine${kind:+ ($kind)}${cpu_arch:+ $cpu_arch}"
