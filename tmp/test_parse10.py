import re

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

print('TOTAL triple-quotes:', dict_src.count('"""'))

# Extract each entry exactly
positions = [m.start() for m in re.finditer(r'    (\d+): ""', dict_src)]
positions.append(len(dict_src))
print('entry start positions:', positions)

for i, v in enumerate([1,2,3,4,5]):
    a = positions[i]
    b = positions[i+1]
    entry = dict_src[a:b]
    n = entry.count('"""')
    print(f'version {v}: entry len={len(entry)}, triples={n}')
    # verify: find the closing
    eq = entry.find('        """,')
    print(f'   has closing """,: {eq > 0}')
