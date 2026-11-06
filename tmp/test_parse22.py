src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Version 5 entry boundaries
v5_s = dict_src.find('    5: """')
v5_e = dict_src.find('        """,', v5_s)
v5 = dict_src[v5_s:v5_e + len('        """,')]
print('=== version 5 entry repr ===')
print(repr(v5))
print()
print('=== version 5 entry with visible escapes ===')
print(v5.replace('\\', '\\\\'))
