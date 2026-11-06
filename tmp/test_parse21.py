src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Version 4 closing + version 5 opening boundary
v4_e = dict_src.find('        """,', dict_src.find('    4: """'))
v5_s = dict_src.find('    5: """')
region = dict_src[v4_e:v5_s + 20]
print('=== raw bytes (repr) ===')
print(repr(region))
print()
print('=== raw bytes (visible) ===')
print(region)
