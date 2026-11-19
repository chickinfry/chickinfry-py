const assert = require("node:assert/strict");
const path = require("node:path");

async function main() {
  const { loadPyodide } = require(path.resolve(process.argv[2], "pyodide"));
  const pyodide = await loadPyodide();
  assert.equal(pyodide.version, "314.0.6");

  const root = path.resolve(__dirname, "../..");
  pyodide.FS.mkdir("/project");
  pyodide.FS.mount(pyodide.FS.filesystems.NODEFS, { root }, "/project");

  const calls = [];
  pyodide.registerJsModule("storage_fixture", {
    async storage(rid, operation, name, key) {
      assert.deepEqual([rid, operation, name], [7, "get", "assets"]);
      calls.push(key);
      switch (key) {
        case "missing": return { value: null };
        case "empty": return { value: new Uint8Array(0) };
        case "unavailable": return { error: "service_unavailable" };
        case "failed": return { error: "operation_failed" };
        case "rejected": throw new Error("fixture storage rejection");
        default: throw new Error("unexpected object key");
      }
    },
  });

  await pyodide.runPythonAsync(`
import glob
import sys
sys.path[:0] = ["/project/src", *glob.glob("/project/wheelhouse/*.whl")]

import js
import pyodide.ffi
import storage_fixture
from chickinfry._workerd import _JSBridge
from chickinfry.server import OperationError

bridge = _JSBridge(storage_fixture, pyodide.ffi, js)
assert await bridge.storage(7, "get", "assets", "missing") is None
empty = await bridge.storage(7, "get", "assets", "empty")
assert type(empty) is bytes and empty == b""

for key, code, status in (
    ("unavailable", "service_unavailable", 503),
    ("failed", "operation_failed", 500),
    ("rejected", "operation_failed", 500),
):
    try:
        await bridge.storage(7, "get", "assets", key)
    except OperationError as error:
        assert (error.code, error.status) == (code, status)
    else:
        raise AssertionError(f"{key} did not raise OperationError")
`);
  assert.deepEqual(calls, ["missing", "empty", "unavailable", "failed", "rejected"]);
  console.log("Pyodide storage port: missing, empty, and error mappings passed");
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
