import ast
import re

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Version 5 entry
v5_s = dict_src.find('    5: """')
print('v5_s:', v5_s)
print('v5_s repr:', repr(dict_src[v5_s:v5_s+12]))

closing = dict_src.find('        """,', v5_s)
print('closing:', closing)
print('closing region:', repr(dict_src[closing-15:closing+15]))

v5 = dict_src[v5_s:closing + 12]
print('v5.count(""""):', v5.count('"""'))
