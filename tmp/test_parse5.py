import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Find each migration entry
import re
# Find the closing of each entry: "    N: ..." followed by content
entries = []
for m in re.finditer(r'    (\d+): ""\"\\*', dict_src):
    version = m.group(1)
    # find the closing triple quote
    inner = dict_src[m.end():]
    end_quote = inner.find('        """,')
    if end_quote == -1:
        print('v'+version, 'NO CLOSING FOUND')
        continue
    entry = dict_src[m.start():m.start() + end_quote + len('        """,')]
    entries.append((version, len(entry)))

for v, l in entries:
    print(f'version {v}: entry length {l}')

# Now test the full dict
try:
    ast.parse(dict_src)
    print('FULL DICT OK')
except SyntaxError as e:
    print('FULL DICT ERROR:', e)
    lines = dict_src.splitlines()
    for i in range(max(0, e.lineno-3), min(len(lines), e.lineno+2)):
        print(i+1, repr(lines[i]))
