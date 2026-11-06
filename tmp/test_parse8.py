import re

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

print('total triple-quotes:', dict_src.count('"""'))

for m in re.finditer(r'    (\d+): ""', dict_src):
    v = m.group(1)
    # count quotes in a window around this version
    rest = dict_src[m.start():m.start()+800]
    n = rest.count('"""')
    print(f'version {v}: triple-quote count in window = {n}')
    print('   head:', repr(rest[:70]))
