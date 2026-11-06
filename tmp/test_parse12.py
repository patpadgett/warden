import ast

# Extract the exact _MIGRATIONS dict from db.py and test it
src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Find the version 5 entry boundaries
v5_start = dict_src.find('    5: """')
v5_end = dict_src.find('        """,', v5_start)
v5_entry = dict_src[v5_start:v5_end + len('        """,')]

print('=== version 5 entry repr ===')
print(repr(v5_entry))
print()
try:
    ast.parse(v5_entry)
    print('version 5 entry: SYNTAX OK')
except SyntaxError as e:
    print('version 5 entry: SYNTAX ERROR', e)
