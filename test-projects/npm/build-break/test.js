const assert = require("assert");
const select = require("./index");

// nth-check 2.x exports `{ default, parse, compile }` instead of a function,
// so the only fix for the advisory breaks this test.
assert.deepStrictEqual(select("2n+1", 6), [0, 2, 4]);
assert.deepStrictEqual(select("odd", 4), [0, 2]);
console.log("ok");
