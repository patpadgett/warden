x = {    4: """
        -- Invite codes for first-login passkey registration.
        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at REAL NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_invites_user ON invites(user_id);
        CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(token_hash);
        CREATE INDEX IF NOT EXISTS idx_invites_used ON invites(used);
        """,,    5: """\
        -- Add user email address. ``email`` is nullable so that existing
        -- databases without this column carry on; application code supplies
        -- the address when the account is created/invited.
        ALTER TABLE users ADD COLUMN email TEXT
        """,}
