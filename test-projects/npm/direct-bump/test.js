const assert = require("assert");
const flatten = require("./index");

const rows = flatten({ a: { x: 1, y: 2 }, b: { x: 3, y: 4 } }, 1);
assert.deepStrictEqual(rows, [
  ["a", { x: 1, y: 2 }],
  ["b", { x: 3, y: 4 }],
]);
console.log("ok");
