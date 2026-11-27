"""Create a source-only ZIP from an explicit allowlist; never traverse local builds/profiles."""

from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parent
TOP_LEVEL = (
    ".gitignore", "README.md", "SECURITY.md", "CHANGELOG.md", "LICENSE", "requirements.txt",
    "setup.bat", "start.bat", "app.py", "bridge.py", "client.py", "errors.py",
    "login.py", "login_page.html", "meta_secret.py", "protocol.py", "wireless.py",
    "export_source.py",
)
TREES = {
    "tests": {".py"},
    "vivaldi-extension": {".js", ".json"},
    ".github/workflows": {".yml"},
}


def source_files(root=ROOT):
    files = {root / name for name in TOP_LEVEL}
    for folder, extensions in TREES.items():
        files.update(path for path in (root / folder).rglob("*")
                     if path.is_file() and path.suffix in extensions
                     and not path.is_symlink() and "__pycache__" not in path.parts)
    for path in sorted(files):
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"Source missing or unsafe: {path.relative_to(root)}")
        yield path


def main():
    # Import the same release version used by the UI without starting Tk.
    from app import VERSION
    directory = ROOT / "exports"
    directory.mkdir(exist_ok=True)
    output = directory / f"QuestLocal-{VERSION}-source.zip"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in source_files():
            archive.write(path, path.relative_to(ROOT).as_posix())
    print(output)
    print("Source only: no venv, keys, APKs, credentials or diagnostic dumps. Review before publishing.")


if __name__ == "__main__":
    main()
