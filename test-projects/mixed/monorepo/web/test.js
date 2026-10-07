const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const layout = require("./index");

const base = fs.mkdtempSync(path.join(os.tmpdir(), "mendr-fixture-"));
try {
  const dirs = layout(base, { a: { x: 1 }, b: { y: 2 } });
  assert.deepStrictEqual(dirs, [path.join(base, "a"), path.join(base, "b")]);
  assert.ok(dirs.every((d) => fs.statSync(d).isDirectory()));
} finally {
  fs.rmSync(base, { recursive: true, force: true });
}
console.log("ok");
