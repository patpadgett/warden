import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

print('dict src repr (first 500):')
print(repr(dict_src[:500]))
print()
try:
    ast.parse(dict_src)
    print('DICT SYNTAX OK')
except SyntaxError as e:
    print('DICT SYNTAX ERROR:', e)
    lines = dict_src.splitlines()
    for i in range(max(0, e.lineno-4), min(len(lines), e.lineno+4)):
        print(i+1, repr(lines[i]))
