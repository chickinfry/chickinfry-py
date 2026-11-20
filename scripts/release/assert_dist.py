#!/usr/bin/env python3
"""Assert the publishable file set of one wheel and one sdist.

The allowlist is the public boundary of the package: runtime sources, package
metadata, and legal files. Any other entry fails the build instead of reaching
the registry.
"""

from pathlib import Path
import sys
import tarfile
import zipfile

PACKAGE = "chickinfry"
LEGAL = {"LICENSE", "LICENSE.txt", "README.md"}
ROOT_METADATA = {"pyproject.toml", "PKG-INFO", "requirements-dev.txt", ".gitignore"}


def fail(message):
    raise ValueError(message)


def check_path(name):
    if "\\" in name or any(part in ("", ".", "..") for part in name.split("/")):
        fail("noncanonical package path")


def wheel_allowed(name):
    if name in LEGAL:
        return True
    if name.startswith(PACKAGE + "/"):
        return True
    if name.startswith(PACKAGE + "-") and ".dist-info/" in name:
        return True
    return False


def sdist_allowed(name):
    if name in ROOT_METADATA or name in LEGAL:
        return True
    return name.startswith("src/" + PACKAGE + "/")


def wheel_entries(path):
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            name = entry.filename
            check_path(name)
            if not wheel_allowed(name):
                fail("unexpected wheel entry: " + name)
            yield name


def sdist_entries(path):
    with tarfile.open(path, mode="r:gz") as archive:
        roots = set()
        for member in archive:
            name = member.name.rstrip("/")
            check_path(name)
            if not member.isfile():
                fail("nonregular sdist entry")
            roots.add(name.split("/", 1)[0])
            yield name
    if len(roots) != 1:
        fail("sdist must contain exactly one top-level directory")


def relative_sdist_names(path):
    for name in sdist_entries(path):
        relative = name.split("/", 1)[1] if "/" in name else ""
        if not relative:
            fail("sdist entry outside the top-level directory")
        if not sdist_allowed(relative):
            fail("unexpected sdist entry: " + relative)
        yield relative


def single(directory, pattern):
    matches = sorted(Path(directory).glob(pattern))
    if len(matches) != 1:
        fail("expected exactly one " + pattern)
    path = matches[0]
    if path.is_symlink() or not path.is_file():
        fail("expected a regular distribution file")
    return path


def main(argv):
    if len(argv) != 2:
        fail("usage: assert_dist.py DIST_DIRECTORY")
    directory = Path(argv[1])
    wheel = single(directory, "*.whl")
    sdist = single(directory, "*.tar.gz")
    names = list(wheel_entries(wheel))
    if not any(name.startswith(PACKAGE + "/") for name in names):
        fail("wheel does not contain the package")
    relative = list(relative_sdist_names(sdist))
    if not any(name.startswith("src/" + PACKAGE + "/") for name in relative):
        fail("sdist does not contain the package sources")
    print(wheel)
    print(sdist)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print("distribution assertion failed: %s" % (error or type(error).__name__), file=sys.stderr)
        sys.exit(1)
