import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Find the version 5 string boundaries
v5_start = dict_src.find('    5: """')
v5_end = dict_src.find('        """,', v5_start)
# get the v5 string content
v5_content = dict_src[v5_start:v5_end + len('        """,')]
print('V5 ENTRY:')
print(repr(v5_content[:100]))
print('---')
# Test version 5 string alone
import textwrap
try:
    ast.parse(v5_content)
    print('V5 STRING SYNTAX OK')
except SyntaxError as e:
    print('V5 STRING SYNTAX ERROR:', e)
    print('line', e.lineno, 'offset', e.offset)
    lines = v5_content.splitlines()
    for i in range(max(0, e.lineno-2), min(len(lines), e.lineno+2)):
        print(i+1, repr(lines[i]))
