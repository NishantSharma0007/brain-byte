const { exec } = require("child_process");

function executeCommand(command, res) {
  exec(command, (error, output) => {
    if (error) {
      res.status(500).send("Command failed");
      return;
    }

    res.send(output);
  });
}

function runFromRequest(req, res) {
  const command = req.query.command;
  executeCommand(command, res);
}