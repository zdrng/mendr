const Router = require("router");

// A router with one route: GET /hello/:name.
module.exports = function app() {
  const router = Router();
  router.get("/hello/:name", (req, res) => res.end("hello " + req.params.name));
  return router;
};
