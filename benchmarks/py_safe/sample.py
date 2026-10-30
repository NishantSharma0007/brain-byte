import subprocess


def handle_request(request):
    user_value = request.args.get("value")

    subprocess.run(
        ["printf", "%s", user_value],
        check=True,
    )