"""Regenerate the private driver file hashes without changing protocol or driver identity."""

import hashlib
import json
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / "conformance-driver.json"
    declaration = json.loads(path.read_text())
    declaration["requiredAuthSDK"] = True
    files = [
        root / "pyproject.toml",
        root / "requirements-dev.txt",
        root / "requirements.txt",
        *root.glob("conformance/driver/*.py"),
        *root.glob("src/chickinfry/**/*.py"),
        root / "src/chickinfry/py.typed",
        *root.glob("wheelhouse/*.whl"),
    ]
    assert len(files) == len(set(files)) and all(file.is_file() for file in files)
    declaration["files"] = [
        {
            "path": file.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
        }
        for file in sorted(files)
    ]
    path.write_text(json.dumps(declaration, indent=2) + "\n")
    realtime = {**declaration, "protocolVersion": 2}
    path.with_name("conformance-driver-realtime.json").write_text(
        json.dumps(realtime, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
