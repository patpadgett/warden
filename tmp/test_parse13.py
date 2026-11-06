import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Test versions 1-4 (before version 5)
v4_end = dict_src.find('    5: """')
dict_1to4 = dict_src[:v4_end]
print('versions 1-4 len:', len(dict_1to4))
try:
    ast.parse(dict_1to4)
    print('versions 1-4: SYNTAX OK')
except SyntaxError as e:
    print('versions 1-4 SYNTAX ERROR:', e)

# Test the full dict
try:
    ast.parse(dict_src)
    print('FULL DICT: SYNTAX OK')
except SyntaxError as e:
    print('FULL DICT SYNTAX ERROR:', e)
    lines = dict_src.splitlines()
    for i in range(max(0, e.lineno-3), min(len(lines), e.lineno+2)):
        print(i+1, repr(lines[i]))
