import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Version 4 entry
v4_s = dict_src.find('    4: """')
v4_e = dict_src.find('        """,', v4_s)
v4 = dict_src[v4_s:v4_e + len('        """,')]
print('=== VERSION 4 ENTRY (repr) ===')
print(repr(v4))
print()
try:
    ast.parse(v4)
    print('version 4 entry: SYNTAX OK')
except SyntaxError as e:
    print('version 4 entry SYNTAX ERROR:', e)
    lines = v4.splitlines()
    for i in range(max(0, e.lineno-2), min(len(lines), e.lineno+2)):
        print(i+1, repr(lines[i]))
