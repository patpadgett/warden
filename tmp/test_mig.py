import ast

# Reproduce the exact _MIGRATIONS dict as written in db.py (lines 513-533)
src = r'''
_MIGRATIONS = MappingProxyType({
    4: """\
        CREATE TABLE IF NOT EXISTS invites (
        );
        """,
    5: """\
        -- Add user email address
        ALTER TABLE users ADD COLUMN email TEXT
        """,
})
'''

import ast
try:
    ast.parse(src)
    print('SYNTAX OK')
except SyntaxError as e:
    print('SYNTAX ERROR:', e)
