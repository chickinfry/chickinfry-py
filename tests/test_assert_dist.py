"""The publish allowlist must accept the real build and reject extra files."""

import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release" / "assert_dist.py"


class AssertDistTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def wheel(self, names: list[str]) -> None:
        with zipfile.ZipFile(
            self.directory / "chickinfry-0.1.0-py3-none-any.whl", "w"
        ) as archive:
            for name in names:
                archive.writestr(name, b"")

    def sdist(self, names: list[str]) -> None:
        with tarfile.open(
            self.directory / "chickinfry-0.1.0.tar.gz", "w:gz"
        ) as archive:
            for name in names:
                body = b""
                member = tarfile.TarInfo(name)
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))

    def run_script(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-B", str(SCRIPT), str(self.directory)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_accepts_runtime_sources_and_metadata(self) -> None:
        self.wheel(
            [
                "chickinfry/__init__.py",
                "chickinfry-0.1.0.dist-info/METADATA",
            ]
        )
        self.sdist(
            [
                "chickinfry-0.1.0/pyproject.toml",
                "chickinfry-0.1.0/src/chickinfry/__init__.py",
            ]
        )
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_test_tree_in_sdist(self) -> None:
        self.wheel(["chickinfry/__init__.py", "chickinfry-0.1.0.dist-info/METADATA"])
        self.sdist(
            [
                "chickinfry-0.1.0/pyproject.toml",
                "chickinfry-0.1.0/src/chickinfry/__init__.py",
                "chickinfry-0.1.0/tests/test_session.py",
            ]
        )
        result = self.run_script()
        self.assertEqual(result.returncode, 1)

    def test_rejects_extra_wheel_entry(self) -> None:
        self.wheel(
            [
                "chickinfry/__init__.py",
                "chickinfry-0.1.0.dist-info/METADATA",
                "wheelhouse/httpx.whl",
            ]
        )
        self.sdist(
            [
                "chickinfry-0.1.0/pyproject.toml",
                "chickinfry-0.1.0/src/chickinfry/__init__.py",
            ]
        )
        result = self.run_script()
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
