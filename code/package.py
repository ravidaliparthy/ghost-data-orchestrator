"""
Packaging script for HackerRank submission.
Packages README.md, code/, and top-level evaluation/ mirror into code.zip.
Enforces atomic creation, thorough scanning, and exclusion of prohibited directories.
"""
import os
import sys
import zipfile
import hashlib
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINAL_ZIP = os.path.join(REPO_ROOT, "code.zip")

EXCLUDE_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules", "dataset", ".gemini", ".idea", ".vscode"}
EXCLUDE_EXT = {".pyc", ".pyo", ".pyd", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar"}
PROHIBITED_FILES = {".env", "auth.json", "credentials.json", "id_rsa", "id_ed25519"}

def should_include(rel_path):
    parts = rel_path.split("/")
    if any(p in EXCLUDE_DIRS for p in parts):
        return False
    ext = os.path.splitext(rel_path)[1].lower()
    if ext in EXCLUDE_EXT:
        return False
    base = os.path.basename(rel_path)
    if base in PROHIBITED_FILES:
        return False
    return True

def package():
    temp_fd, temp_zip_path = tempfile.mkstemp(suffix=".zip", dir=REPO_ROOT)
    os.close(temp_fd)

    try:
        with zipfile.ZipFile(temp_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # 1. README.md
            readme = os.path.join(REPO_ROOT, "README.md")
            if os.path.exists(readme):
                zf.write(readme, "README.md")

            # 2. code/ directory
            code_dir = os.path.join(REPO_ROOT, "code")
            for root, dirs, files in os.walk(code_dir):
                dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
                for fn in files:
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, REPO_ROOT).replace(os.sep, "/")
                    if should_include(rel):
                        zf.write(full, rel)

            # 3. Top-level evaluation/ mirror
            top_eval = os.path.join(REPO_ROOT, "evaluation")
            if os.path.exists(top_eval):
                for root, dirs, files in os.walk(top_eval):
                    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
                    for fn in files:
                        full = os.path.join(root, fn)
                        rel = os.path.relpath(full, REPO_ROOT).replace(os.sep, "/")
                        if should_include(rel):
                            zf.write(full, rel)

        # Integrity Scan of temp_zip_path
        with zipfile.ZipFile(temp_zip_path, "r") as zf:
            entries = zf.namelist()

        # Sanity scans
        for e in entries:
            assert not e.startswith("dataset/"), f"Prohibited dataset/ file in archive: {e}"
            ext = os.path.splitext(e)[1].lower()
            assert ext not in EXCLUDE_EXT, f"Prohibited nested archive/binary in zip: {e}"
            base = os.path.basename(e)
            assert base not in PROHIBITED_FILES, f"Prohibited credentials/key in zip: {e}"

        # Verify required files exist in zip
        required = [
            "README.md",
            "code/main.py",
            "code/INTERVIEW_NOTES.md",
            "code/evaluation/evaluation_report.md",
            "code/evaluation/usage_report.md",
            "evaluation/evaluation_report.md",
            "evaluation/usage_report.md",
        ]
        for req in required:
            assert req in entries, f"Required entry missing from package: {req}"

        # Atomic replacement
        os.replace(temp_zip_path, FINAL_ZIP)

        h = hashlib.sha256(open(FINAL_ZIP, "rb").read()).hexdigest()
        size_kb = os.path.getsize(FINAL_ZIP) / 1024

        print(f"Packaged {len(entries)} entries into {FINAL_ZIP}")
        print(f"Archive Size: {size_kb:.1f} KB")
        print(f"Archive SHA-256: {h}")
        print("\nVerified Archive Entries:")
        for e in sorted(entries):
            print(f"  {e}")

    finally:
        if os.path.exists(temp_zip_path):
            try:
                os.remove(temp_zip_path)
            except Exception:
                pass

if __name__ == "__main__":
    package()
