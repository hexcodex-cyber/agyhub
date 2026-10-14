#!/usr/bin/env python3
"""Stand-in for agy. Speaks the bits agyhub drives. Not the real CLI."""

import json
import os
import sys
import time


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def models():
    token = os.environ.get("AGY_TOKEN_FILE", "")
    if token and os.path.isfile(token) and os.path.getsize(token) > 0:
        print("gemini-test Gemini Test")
        return 0
    print("Please sign in to view available models.", file=sys.stderr)
    return 1


def stream():
    args = sys.argv[1:]
    conv = "conv-new"
    if "--conversation" in args:
        conv = args[args.index("--conversation") + 1]
    emit({
        "event": "init",
        "conversation_id": conv,
        "init": {"cwd": os.getcwd(), "tools": ["run_command"], "permission_mode": "request-review"},
    })
    while True:
        line = sys.stdin.readline()
        if not line:
            return 0
        msg = json.loads(line)
        content = msg.get("message", {}).get("content") or ""
        if content == "sleep":
            for _ in range(300):
                time.sleep(0.05)
            emit({
                "event": "result",
                "result": {"conversation_id": conv, "status": "CANCELED", "response": "", "error": ""},
            })
            continue
        emit({
            "event": "step_update",
            "step_update": {
                "conversation_id": conv,
                "step_index": 1,
                "state": "ACTIVE",
                "step_type": "agent_response",
                "text_delta": "Hello ",
            },
        })
        emit({
            "event": "step_update",
            "step_update": {
                "conversation_id": conv,
                "step_index": 2,
                "state": "DONE",
                "step_type": "tool",
                "tool_name": "run_command",
                "tool_info": {"name": "run_command", "parameters": {"CommandLine": "echo hi"}, "output": "hi\n"},
            },
        })
        emit({
            "event": "step_update",
            "step_update": {
                "conversation_id": conv,
                "step_index": 3,
                "state": "DONE",
                "step_type": "agent_response",
                "text_delta": content.splitlines()[0] if content else "",
            },
        })
        emit({
            "event": "result",
            "result": {
                "conversation_id": conv,
                "status": "SUCCESS",
                "response": "Hello " + content,
            },
        })


def login():
    sys.stdout.write("Select login method:\n > 1. Google OAuth\n")
    sys.stdout.flush()
    sys.stdin.readline()
    url = (
        "https://accounts.google.com/o/oauth2/auth?client_id=test"
        ".apps.googleusercontent.com&response_type=code&state=abc"
    )
    sys.stdout.write("\x1b]8;;" + url + "\x07")
    sys.stdout.write("Open the URL below in your browser:\n" + url + "\n")
    sys.stdout.write("paste the authorization code below:\n")
    sys.stdout.flush()
    code = sys.stdin.readline().strip()
    token = os.environ.get("AGY_TOKEN_FILE", "")
    if code == "good-code" and token:
        fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("token\n")
        sys.stdout.write("signed in\n")
        sys.stdout.flush()
        time.sleep(1)
        return 0
    sys.stdout.write("invalid code\n")
    sys.stdout.flush()
    return 1


def main():
    args = sys.argv[1:]
    if "models" in args:
        return models()
    if "--input-format" in args:
        return stream()
    return login()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        emit({
            "event": "result",
            "result": {"conversation_id": "", "status": "INTERRUPTED", "response": "", "error": ""},
        })
        sys.exit(0)
