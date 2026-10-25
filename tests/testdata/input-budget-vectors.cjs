// Regenerate with the Node version pinned by the CLI's mise.toml.
const fs = require("node:fs");
const path = require("node:path");

const scalars = [
  "null", "true", "false", "0", "-0", "0.0", "-0.0", "0e100", "1", "-1", "1.0",
  "1e-7", "-1e-7", "1e-6", "9.999999999999999e-7", "0.0000010000000000000002",
  "1e20", "1e21", "-1e20", "-1e21", "999999999999999999999", "1000000000000000100",
  "9007199254740991", "9007199254740992", "9007199254740993", "9007199254740995",
  "1e308", "1.7976931348623157e308", "1e309", "-1e309", "5e-324", "1e-325", "-1e-325",
  "0.1", "333333333.33333329", "1424953923781206.25", "2.2250738585072014e-308",
  "1" + "0".repeat(400), "-" + "1" + "0".repeat(400),
  '"\\ud800"', '"\\udfff"', '"\\ud83d\\ude00"', '"\\u4e16\\u754c"',
  '"\\u2028\\u2029"', '"\\u0000\\b\\f\\n\\r\\t\\\"\\\\"',
];
const cases = [];
function add(name, raw) {
  cases.push({name, raw, bytes: Buffer.byteLength(JSON.stringify(JSON.parse(raw)), "utf8")});
}
for (const [index, raw] of scalars.entries()) {
  add("scalar-" + index, '{"known":"ok","ignored":' + raw + "}");
}
add("nested-scalars", '{"known":"ok","ignored":[1e20,1e-7,-0,9007199254740993,null,true,"\\ud800",{"\\udfff":"\\u4e16\\u754c"}]}');

let seed = 0x9e3779b9;
function next() {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return seed >>> 0;
}
const bits = Buffer.alloc(8);
for (let index = 0; index < 10000; index++) {
  bits.writeUInt32BE(next(), 0);
  bits.writeUInt32BE(next(), 4);
  const value = bits.readDoubleBE(0);
  if (Number.isFinite(value)) {
    add("binary64-" + index, '{"ignored":' + value.toExponential(16) + "}");
  }
}
fs.writeFileSync(path.join(__dirname, "input-budget-vectors.json"), JSON.stringify({
  node: process.version,
  oracle: "Buffer.byteLength(JSON.stringify(JSON.parse(raw)), 'utf8')",
  cases,
}, null, 2) + "\n");
console.log("Input budget oracle vectors: " + cases.length);
