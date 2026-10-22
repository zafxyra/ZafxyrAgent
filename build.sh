#!/usr/bin/env bash
# 交叉编译 agentd 到 Android arm64。
#
# 需要 Go 1.21+。CGO 关掉，产物是纯静态 ELF，直接丢到手机就能跑。
# 用法: ./build.sh [输出路径]
set -euo pipefail
cd "$(dirname "$0")"

OUT="${1:-ai-agent-module/module/bin/agentd}"

cd ai-agent-module/src
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w" -o "../../$OUT" main.go

cd ../..
SIZE=$(wc -c < "$OUT")
echo "built: $OUT (${SIZE} bytes)"
python -c "
d = open(r'$OUT','rb').read(20)
assert d[:4] == b'\x7fELF', 'not an ELF'
print('arch: aarch64' if int.from_bytes(d[18:20],'little')==183 else 'arch: ???')
"
