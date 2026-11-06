import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Find versions
v1_s = dict_src.find('    1: """')
v2_s = dict_src.find('    2: """')
v3_s = dict_src.find('    3: """')
v4_s = dict_src.find('    4: """')
v5_s = dict_src.find('    5: """')

def get_entry(a, b):
    return dict_src[a:b]

v1 = get_entry(v1_s, v2_s)
v2 = get_entry(v2_s, v3_s)
v3 = get_entry(v3_s, v4_s)
v4 = get_entry(v4_s, v5_s)

for name, v in [('v1', v1), ('v2', v2), ('v3', v3), ('v4', v4)]:
    try:
        ast.parse(v)
        print(f'{name}: SYNTAX OK ({len(v)} chars)')
    except SyntaxError as e:
        print(f'{name}: SYNTAX ERROR {e}')
