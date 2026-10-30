const { executeCommand } = require("./command_runner");

function handleRequest(req) {
  const command = req.query.command;
  executeCommand(command);
}

module.exports = { handleRequest };