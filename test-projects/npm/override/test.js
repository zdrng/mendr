const assert = require("assert");
const app = require("./index");

const req = { method: "GET", url: "/hello/world" };
const res = {
  end(body) {
    assert.strictEqual(body, "hello world");
    console.log("ok");
  },
};
app()(req, res, (err) => {
  throw err || new Error("route not matched");
});
