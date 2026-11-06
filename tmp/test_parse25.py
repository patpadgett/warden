src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Version 4 entry: find the exact boundaries
v4_s = dict_src.find('    4: """')
v4_e = dict_src.find('        """,', v4_s)
v4 = dict_src[v4_s:v4_e + len('        """,')]

print('=== version 4 entry repr (first 400) ===')
print(repr(v4[:400]))
print()
# Check: does the version 4 entry have an even number of triple-quotes?
print('triple-quotes in v4:', v4.count('"""'))
print('triple-quotes in v5:', dict_src[dict_src.find('    5: """'):dict_src.find('    5: """')+200].count('"""'))
