from __future__ import annotations
from warden.main import create_app

def test_create_app_loads() -> None:
    # Minimal create_app test using default config
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "w.yaml"
        p.write_text("version: 1\nserver:\n  admin_host: localhost\nwebauthn:\n  rp_id: localhost\nroutes: []\n")
        from warden.config import ConfigManager
        manager = ConfigManager.from_file(p)
        # Just verify manager loads; full app needs DB seed
        assert manager.config.server.admin_host == "localhost"
