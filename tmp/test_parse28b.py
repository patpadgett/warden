import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Test version 1 only
v1_s = dict_src.find('    1: """')
v1_e = dict_src.find('    2: """')
v1 = dict_src[v1_s:v1_e]
print('=== version 1 repr (first 500) ===')
print(repr(v1[:500]))
print()
try:
    ast.parse(v1)
    print('version 1: SYNTAX OK')
except SyntaxError as e:
    print('version 1 SYNTAX ERROR:', e)
    lines = v1.splitlines()
    for i in range(max(0, e.lineno-3), min(len(lines), e.lineno+3)):
        print(i+1, repr(lines[i]))
