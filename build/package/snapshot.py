#!/usr/bin/python3
"""Deterministic source-only archive. Excludes local evidence, credentials and .git."""
import gzip
import hashlib
import io
import pathlib
import sys
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
DIRECTORIES = ("bin", "src", "tests", "build", "docs", "compatibility")
FILES = (".gitignore", "README.md", "SECURITY.md", "CHANGELOG.md", "OLS-cPanel-Production-Plan-v3.md")

def entries():
    paths = [ROOT / name for name in FILES if (ROOT / name).is_file()]
    for directory in DIRECTORIES:
        paths.extend(p for p in (ROOT / directory).rglob("*") if p.is_file()
            and "__pycache__" not in p.parts and p.suffix != ".pyc")
    for path in sorted(set(paths)):
        if path.is_symlink():
            raise ValueError("Symlinks are not allowed in the source snapshot")
        yield path.relative_to(ROOT).as_posix(), path.read_bytes()

def archive():
    target = io.BytesIO()
    with gzip.GzipFile(fileobj=target, mode="wb", mtime=0, filename="") as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, data in entries():
                info = tarfile.TarInfo("OLS-cPanel-WHM/" + name)
                info.size, info.mode, info.uid, info.gid, info.mtime = len(data), 0o644, 0, 0, 0
                tar.addfile(info, io.BytesIO(data))
    return target.getvalue()

if __name__ == "__main__":
    data = archive()
    if len(sys.argv) == 2:
        # Do not overwrite an existing artifact.
        with open(sys.argv[1], "xb") as handle:
            handle.write(data)
    print(hashlib.sha256(data).hexdigest())
