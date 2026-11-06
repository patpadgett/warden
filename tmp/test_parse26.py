import re

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Version 5 entry
v5_s = dict_src.find('    5: """')
print('v5_s:', v5_s)
print('v5_s repr:', repr(dict_src[v5_s:v5_s+15]))

# Find the closing
closing = dict_src.find('        """,', v5_s)
print('closing found at:', closing)

# Print the region around the closing
if closing != -1:
    print('closing region:', repr(dict_src[closing-20:closing+15]))
