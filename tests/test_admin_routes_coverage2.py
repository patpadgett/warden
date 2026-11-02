from __future__ import annotations


def test_admin_audit_export_import() -> None:
    # Just ensures import succeeds
    from warden.admin.routes import audit_export
    assert callable(audit_export)
