const jsprim = require("jsprim");

// Deep-copy `obj` and flatten it to `depth` levels.
module.exports = function flatten(obj, depth) {
  return jsprim.flattenObject(jsprim.deepCopy(obj), depth);
};
