import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]
print('LEN', len(dict_src))
try:
    ast.parse(dict_src)
    print('DICT SYNTAX OK')
except SyntaxError as e:
    print('DICT SYNTAX ERROR:', e)
