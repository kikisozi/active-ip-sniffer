from pathlib import Path
p = Path('.patch-v341.py')
s = p.read_text(encoding='utf-8')
old = "'''\\texit 6\\nfi\\n\\n# Do not copy directly over a running executable'''"
new = "'''  exit 6\\nfi\\n\\n# Do not copy directly over a running executable'''"
if old not in s:
    raise SystemExit('patch matcher to fix was not found')
p.write_text(s.replace(old, new, 1), encoding='utf-8')
