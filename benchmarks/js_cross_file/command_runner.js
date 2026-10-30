const { exec } = require("child_process");

function executeCommand(command) {
  exec(command, () => {});
}

module.exports = { executeCommand };