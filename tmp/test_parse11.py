import re

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

print('dict_src length:', len(dict_src))

# For each version, find the closing """, correctly
for m in re.finditer(r'    (\d+): ""', dict_src):
    v = m.group(1)
    a = m.start()
    # Find the closing """, starting from a
    b = dict_src.find('        """,', a)
    entry = dict_src[a:b]
    print(f'version {v}: start={a}, closing at {b}, entry len={len(entry)}')
