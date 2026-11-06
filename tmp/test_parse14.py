import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Extract versions 1-4
v4_end = dict_src.find('    5: """')
dict_1to4 = dict_src[:v4_end]
print('versions 1-4 len:', len(dict_1to4))

# Find the version 4 entry boundaries
v4_start = dict_src.find('    4: """')
v4_end = dict_src.find('        """,', v4_start)
v4_entry = dict_src[v4_start:v4_end + len('        """,')]
print('=== version 4 entry repr ===')
print(repr(v4_entry[:80]))
print('...')
print(repr(v4_entry[-80:]))
print()

try:
    ast.parse(v4_entry)
    print('version 4 entry: SYNTAX OK')
except SyntaxError as e:
    print('version 4 entry SYNTAX ERROR:', e)
