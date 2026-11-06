import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Version 4 entry
v4_s = dict_src.find('    4: """')
v4_e = dict_src.find('        """,', v4_s)
v4 = dict_src[v4_s:v4_e + len('        """,')]

# Version 5 entry
v5_s = dict_src.find('    5: """')
v5_e = dict_src.find('        """,', v5_s)
v5 = dict_src[v5_s:v5_e + len('        """,')]

# Test version 4 + version 5 concatenated
combined = "{" + v4 + "," + v5 + "}\n"
print('=== COMBINED version 4 + 5 ===')
print(repr(combined[:300]))
print()
try:
    ast.parse(combined)
    print('version 4 + 5: SYNTAX OK')
except SyntaxError as e:
    print('version 4 + 5 SYNTAX ERROR:', e)
    lines = combined.splitlines()
    for i in range(max(0, e.lineno-3), min(len(lines), e.lineno+2)):
        print(i+1, repr(lines[i]))
