import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Test versions 1-3 (before version 4)
v3_end = dict_src.find('    4: """')
dict_123 = dict_src[:v3_end]
print('=== versions 1-3 len:', len(dict_123))
try:
    ast.parse(dict_123)
    print('versions 1-3: SYNTAX OK')
except SyntaxError as e:
    print('versions 1-3 SYNTAX ERROR:', e)
    lines = dict_123.splitlines()
    for i in range(max(0, e.lineno-3), min(len(lines), e.lineno+3)):
        print(i+1, repr(lines[i]))
