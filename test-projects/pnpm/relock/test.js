const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const makeTree = require("./index");

const base = fs.mkdtempSync(path.join(os.tmpdir(), "mendr-fixture-"));
try {
  assert.ok(fs.statSync(makeTree(base)).isDirectory());
} finally {
  fs.rmSync(base, { recursive: true, force: true });
}
console.log("ok");
