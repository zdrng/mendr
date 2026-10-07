const path = require("path");
const jsprim = require("jsprim");
const mkdirp = require("mkdirp");

// Flatten `obj` one level deep and create one directory per top-level key.
module.exports = function layout(base, obj) {
  const rows = jsprim.flattenObject(jsprim.deepCopy(obj), 1);
  return rows.map(([key]) => {
    const dir = path.join(base, key);
    mkdirp.sync(dir);
    return dir;
  });
};
