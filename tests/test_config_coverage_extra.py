from warden.config import parse_config_text, ConfigError
from pathlib import Path
import tempfile

def test_parse_config_text_valid() -> None:
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
        f.write("version: 1\nserver:\n  admin_host: localhost\nwebauthn:\n  rp_id: localhost\nroutes: []\n")
        p = f.name
    text = Path(p).read_text()
    cfg = parse_config_text(text, base_dir=Path(p).parent)
    assert cfg.version == 1
