import subprocess


def run_command(command):
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    )


def handle_request(request):
    user_command = request.args.get("command", "")
    run_command(user_command)