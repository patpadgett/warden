import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Find version 5 entry
v5_start = dict_src.find('    5: """')
v5_end = dict_src.find('        """,', v5_start)
v5_content = dict_src[v5_start:v5_end + len('        """,')]

# Test version 5 entry using ast with the dict context
# Wrap in a test
import textwrap
test = 'x = {' + v5_content + '\n}'
try:
    ast.parse(test)
    print('V5 AS PART OF DICT: OK')
except SyntaxError as e:
    print('V5 AS PART OF DICT ERROR:', e)
    lines = test.splitlines()
    for i in range(max(0, e.lineno-2), min(len(lines), e.lineno+2)):
        print(i+1, repr(lines[i]))
