import re

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

for m in re.finditer(r'    (\d+): ""', dict_src):
    v = m.group(1)
    # count all """ in this entry
    rest = dict_src[m.start():]
    # determine entry boundaries: entries are separated by "    N: \"\"\""
    entry_end = dict_src.find('\n    ', m.end())
    if entry_end == -1:
        entry_end = len(dict_src)
    chunk = dict_src[m.start():entry_end]
    n = chunk.count('"""')
    print(f'version {v}: triple-quote count = {n}')
