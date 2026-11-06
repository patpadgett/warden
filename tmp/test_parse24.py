import ast
import re

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Find version boundaries
positions = [m.start() for m in re.finditer(r'    (\d+): ""', dict_src)]
positions.append(len(dict_src))

import re
for i in range(1, 6):
    a = positions[i-1]
    b = positions[i]
    entry = dict_src[a:b]
    try:
        ast.parse(entry)
        print(f'version {i}: OK ({len(entry)} chars)')
    except SyntaxError as e:
        print(f'version {i}: SYNTAX ERROR: {e}')
        lines = entry.splitlines()
        for j in range(max(0, e.lineno-3), min(len(lines), e.lineno+3)):
            print(f'   {j+1}: {repr(lines[j])}')
