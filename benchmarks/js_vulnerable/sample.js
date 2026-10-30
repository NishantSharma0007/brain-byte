const { exec } = require("child_process");

function executeCommand(command) {
  exec(command, () => {});
}

function handleRequest(req) {
  const command = req.query.command;
  executeCommand(command);
}