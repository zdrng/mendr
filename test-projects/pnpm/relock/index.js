const path = require("path");
const mkdirp = require("mkdirp");

// Create `<base>/a/b` and return its path.
module.exports = function makeTree(base) {
  const dir = path.join(base, "a", "b");
  mkdirp.sync(dir);
  return dir;
};
