import subprocess


def run_command(command):
    subprocess.run(command, shell=True, check=False)


def handle_request(request):
    user_command = request.args.get("command")
    run_command(user_command)