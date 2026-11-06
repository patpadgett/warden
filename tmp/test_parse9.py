import re

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Find each entry
for m in re.finditer(r'    (\d+): ""', dict_src):
    v = m.group(1)
    rest = dict_src[m.start():]
    # find the closing triple-quote of this entry
    eq = rest.find('        """,')
    if eq == -1:
        print(f'version {v}: NO CLOSING FOUND'); continue
    entry = rest[:eq + len('        """,')]
    n = entry.count('"""')
    print(f'version {v}: triple-quotes = {n}, entry len = {len(entry)}')
    # print the entry's position in dict_src
    print(f'   position: {m.start()}-{m.start()+len(entry)}')
