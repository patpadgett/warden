import ast

src = open('/home/pat/projects/warden/warden/db.py').read()
start = src.find('_MIGRATIONS: MappingProxyType = MappingProxyType({')
end = src.find('})  # type: ignore[assignment]', start)
dict_src = src[start:end]

# Version 4 entry
v4_s = dict_src.find('    4: """')
v4_e = dict_src.find('        """,', v4_s)
v4 = dict_src[v4_s:v4_e + len('        """,')]

# Version 5 entry
v5_s = dict_src.find('    5: """')
v5_e = dict_src.find('        """,', v5_s)
v5 = dict_src[v5_s:v5_e + len('        """,')]

# Write to a file and py_compile
combined = "x = {" + v4 + "," + v5 + "}\n"
with open('/home/pat/projects/warden/tmp/combined.py', 'w') as f:
    f.write(combined)

import subprocess
r = subprocess.run(['timeout', '30', '.venv/bin/python', '/home/pat/projects/warden/tmp/combined.py'],
                   capture_output=True, text=True)
print('STDOUT:', r.stdout)
print('STDERR:', r.stderr)
print('EXIT:', r.returncode)
