"""
Test that current vs historical identifiers resolve to the identical user_id and consistent search keys.
"""
import os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "code"))

from engine.identity_resolver import IdentityResolver
from engine.common import load_csv

def test_historical_email_resolution():
    dataset_dir = os.path.join(ROOT, "dataset")
    ident = IdentityResolver(os.path.join(dataset_dir, "user_identities.csv"), os.path.join(dataset_dir, "user_audit_log.csv"))
    ident.load()

    audit_rows = load_csv(os.path.join(dataset_dir, "user_audit_log.csv"))
    email_changes = [r for r in audit_rows if r.get("field_name") == "email" and r.get("old_value")]

    assert len(email_changes) > 0, "Expected email changes in audit log"

    for change in email_changes[:15]:
        uid = change["user_id"]
        old_email = change["old_value"]
        new_email = change["new_value"]
        change_time = change["event_time"]

        res_old = ident.resolve(old_email, change_time, "2026-09-30T23:59:59Z")
        res_new = ident.resolve(new_email, change_time, "2026-09-30T23:59:59Z")

        assert uid in res_old.user_ids, f"Old email {old_email} did not resolve to {uid}"
        assert uid in res_new.user_ids, f"New email {new_email} did not resolve to {uid}"
        assert res_old.status == "RESOLVED"
        assert res_new.status == "RESOLVED"

if __name__ == "__main__":
    test_historical_email_resolution()
    print("test_historical_email_resolution: PASS")
