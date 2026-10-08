const nthCheck = require("nth-check");

// Indexes (0-based) of the elements `:nth-child(<formula>)` selects among `count`.
module.exports = function select(formula, count) {
  const check = nthCheck(formula);
  const picked = [];
  for (let i = 0; i < count; i++) {
    if (check(i)) picked.push(i);
  }
  return picked;
};
