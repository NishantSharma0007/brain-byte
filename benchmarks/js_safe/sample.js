const { execFile } = require("child_process");

const allowedActions = new Set(["status", "help"]);

function handleRequest(req) {
  const action = req.query.action;

  if (!allowedActions.has(action)) {
    throw new Error("Unsupported action");
  }

  execFile("my-tool", [action]);
}