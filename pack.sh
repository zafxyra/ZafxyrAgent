#!/usr/bin/env bash
# 打包成可刷入的模块 zip。
#
# 关键：必须把文本文件统一转成 LF。
# Windows 上 git 会把 .sh / module.prop / update-binary 自动转成 CRLF，
# 直接打包刷进手机会让 sh 报 "syntax error: unexpected end of file"，
# 甚至 install 脚本本身都跑不起来。
set -euo pipefail
cd "$(dirname "$0")"

OUT="${1:-aiagent.zip}"

python - "$OUT" <<'PY'
import os
import sys
import zipfile

out = sys.argv[1]
root = 'ai-agent-module/module'

# 无扩展名但确实是脚本的文件
SCRIPT_NAMES = {'update-binary', 'updater-script'}
# 必须保持原样的二进制
BINARY_NAMES = {'agentd'}
TEXT_EXT = {'.sh', '.prop', '.json', '.xml', '.md', '.pem', '.txt'}


def is_text(arc: str) -> bool:
    base = os.path.basename(arc)
    if base in BINARY_NAMES:
        return False
    if base in SCRIPT_NAMES:
        return True
    return os.path.splitext(base)[1].lower() in TEXT_EXT


converted = []
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    for dp, _, files in os.walk(root):
        for f in sorted(files):
            full = os.path.join(dp, f)
            arc = os.path.relpath(full, root).replace('\\', '/')
            if is_text(arc):
                data = open(full, 'rb').read()
                if b'\r\n' in data:
                    data = data.replace(b'\r\n', b'\n')
                    converted.append(arc)
                # writestr 保证内容与行尾完全按我们给的来
                info = zipfile.ZipInfo(arc)
                info.external_attr = 0o755 << 16 if arc.endswith('.sh') or arc in SCRIPT_NAMES else 0o644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, data)
            else:
                z.write(full, arc)

# 打包后自检：关键脚本里不能再有 CR
problems = []
with zipfile.ZipFile(out) as z:
    for n in z.namelist():
        if is_text(n) and b'\r' in z.read(n):
            problems.append(n)

print('packed:', out)
print('files  :', len(zipfile.ZipFile(out).namelist()))
print('crlf->lf:', ', '.join(converted) if converted else '(无需转换)')
print('residual CR:', problems if problems else '无')
if problems:
    sys.exit(1)
PY
