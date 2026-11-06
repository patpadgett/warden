import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
# Extract the _MIGRATIONS dict assignment
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
if end == -1:
    # fallback: find the closing of the dict
    depth = 0
    in_str = False
    quote = None
    for i in range(start, len(src)):
        ch = src[i]
        if in_str:
            if ch == '\\':
                continue
            if ch == quote:
                in_str = False
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                break
if end == -1:
    print('DICT NOT FOUND')
else:
    dict_src = src[start:end]
    try:
        ast.parse(dict_src)
        print('DICT SYNTAX OK')
    except SyntaxError as e:
        print('DICT SYNTAX ERROR:', e)
        print('line', e.lineno, 'offset', e.offset)
        lines = dict_src.splitlines()
        for i in range(max(0, e.lineno-3), min(len(lines), e.lineno+2)):
            print(i+1, repr(lines[i]))
