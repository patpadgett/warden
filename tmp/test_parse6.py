import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Count triple-quote occurrences
import re
triples = re.findall(r'"""', dict_src)
print('triple-quote count:', len(triples), '==>', len(triples) % 2)

# Print the version 4 and version 5 entries with repr
for m in re.finditer(r'    (\d+): ""\"', dict_src):
    v = m.group(1)
    # find end of this entry
    rest = dict_src[m.end():]
    eq = rest.find('        """,')
    entry = rest[:eq + len('        """,')]
    print(f'version {v}: entry repr head =', repr(entry[:60]))
    print(f'              tail =', repr(entry[-40:]))
