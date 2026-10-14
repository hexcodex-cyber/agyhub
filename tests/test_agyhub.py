#!/usr/bin/env python3
"""agyhub against tests/fake_agy.py. No Google account and no real agy."""

import asyncio
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import server  # noqa: E402

FAKE = str(ROOT / "tests" / "fake_agy.py")


def oauth_fixture():
    return (
        "Open the URL below in your browser:\n"
        " https://accounts.google.com/o/oauth2/auth?client_id=test\n"
        " .apps.googleusercontent.com&response_type=code&state=abc\n"
        "\n"
        " Copy and paste the URL\n"
    ).encode()


class PureTests(unittest.TestCase):
    def test_wrapped_url(self):
        url = server.extract_oauth_url(oauth_fixture())
        self.assertEqual(
            url,
            "https://accounts.google.com/o/oauth2/auth?client_id=test.apps.googleusercontent.com"
            "&response_type=code&state=abc",
        )

    def test_osc_url(self):
        raw = (
            b"noise \x1b]8;;https://accounts.google.com/o/oauth2/auth?"
            b"client_id=osc&response_type=code&state=s\x07click"
        )
        self.assertEqual(
            server.extract_oauth_url(raw),
            "https://accounts.google.com/o/oauth2/auth?client_id=osc&response_type=code&state=s",
        )

    def test_osc_with_params_beats_wrapped_first_line(self):
        full = (
            "https://accounts.google.com/o/oauth2/auth?client_id=abc"
            "&response_type=code&state=xyz"
        )
        raw = b"\x1b]8;id=abcdefghijkl;" + full.encode() + b"\x07" + full[:40].encode() + b"\n\n"
        self.assertEqual(server.extract_oauth_url(raw), full)

    def test_blank_lines_between_wrapped_pieces(self):
        full = (
            "https://accounts.google.com/o/oauth2/auth?client_id=test.apps.googleusercontent.com"
            "&response_type=code&state=abc"
        )
        parts = [full[i:i + 30] for i in range(0, len(full), 30)]
        raw = ("\n\n".join(parts) + "\n\n" + ("─" * 8) + "\n").encode()
        self.assertEqual(server.extract_oauth_url(raw), full)

    def test_partial_wrap_is_not_a_link(self):
        raw = b"https://accounts.google.com/o/oauth2/auth?client_id=test&response_type=code\n"
        self.assertEqual(server.extract_oauth_url(raw), "")

    def test_tool_step(self):
        updates = server.map_step({
            "step_index": 4,
            "state": "DONE",
            "step_type": "tool",
            "tool_name": "run_command",
            "tool_info": {"parameters": {"CommandLine": "echo hi"}, "output": "hi\n"},
        })
        self.assertEqual(updates[0]["title"], "run_command")
        self.assertEqual(updates[0]["status"], "done")
        self.assertIn("echo hi", updates[0]["body"])

    def test_turn_stop(self):
        self.assertEqual(server.turn_stop({"status": "SUCCESS"})[0], "end_turn")
        self.assertEqual(server.turn_stop({"status": "INTERRUPTED"})[0], "cancelled")
        self.assertEqual(server.turn_stop({"status": "ERROR", "error": "nope"})[1], "nope")

    def test_totp_replay_window(self):
        secret = "JBSWY3DPEHPK3PXP"
        now = 1_700_000_000
        code = server.totp_code(secret, now)
        self.assertEqual(server.totp_step(secret, code, now=now), int(now) // 30)
        self.assertIsNone(server.totp_step(secret, "000000", now=now))


class HubTests(unittest.TestCase):
    def setUp(self):
        server._fails.clear()
        server._sessions.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["AGYHUB_ROOT"] = str(self.root)
        os.environ["AGYHUB_PASSWORD"] = "test-password-123"
        os.environ["AGY_TOKEN_FILE"] = str(self.root / "token")
        server.setup(False)
        self.secrets = server.load_secrets()

    def tearDown(self):
        self.tmp.cleanup()

    def _app(self):
        store = server.Store(self.root / "data")
        agent = server.Agent(FAKE, self.root / "work", self.root / "token", store, False, False, "1m")
        google = server.GoogleLogin(FAKE, self.root / "token")
        return server.build_app(self.secrets, agent, google, False, "")

    def _code(self):
        return server.totp_code(self.secrets["totp_secret"], time.time())

    def test_cookie_secure_only_on_https(self):
        direct = types.SimpleNamespace(
            remote="203.0.113.10", scheme="http", headers={},
            app={"secure_cookie": True, "trusted_proxy": "203.0.113.20"},
        )
        proxied = types.SimpleNamespace(
            remote="203.0.113.20", scheme="http",
            headers={"X-Forwarded-Proto": "https"},
            app={"secure_cookie": True, "trusted_proxy": "203.0.113.20"},
        )
        self.assertFalse(server.cookie_secure(direct))
        self.assertTrue(server.cookie_secure(proxied))

    def test_chat_and_login(self):
        asyncio.run(self._chat_and_login())

    async def _chat_and_login(self):
        from aiohttp.test_utils import TestClient, TestServer

        app = self._app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.post("/login", data={
                "password": "test-password-123",
                "totp": self._code(),
            }, allow_redirects=False)
            self.assertEqual(resp.status, 302)
            origin = f"http://{client.host}:{client.port}"
            ws = await client.ws_connect("/ws", headers={"Origin": origin})
            first = await ws.receive_json()
            self.assertEqual(first["op"], "auth")
            self.assertFalse(first["signed_in"])

            started = await ws.send_json({"op": "login_start"})
            login = await ws.receive_json()
            self.assertEqual(login["op"], "login")
            self.assertTrue(login["url"].startswith("https://accounts.google.com/"))
            self.assertNotIn("code_challenge", login["url"])  # the fake URL is the short one

            await ws.send_json({"op": "login_code", "code": "good-code"})
            done = await ws.receive_json()
            self.assertEqual(done, {"op": "login", "phase": "done"})
            authed = await ws.receive_json()
            self.assertTrue(authed["signed_in"])

            await ws.send_json({"op": "new"})
            opened = await ws.receive_json()
            self.assertEqual(opened["op"], "opened")
            sid = opened["id"]
            await ws.send_json({"op": "prompt", "id": sid, "text": "there"})
            kinds = []
            stop = ""
            for _ in range(12):
                msg = await ws.receive_json()
                if msg["op"] == "update":
                    kinds.append(msg["kind"])
                elif msg["op"] == "done":
                    stop = msg["stop"]
                    break
                elif msg["op"] == "error":
                    self.fail(msg)
            self.assertEqual(stop, "end_turn")
            self.assertIn("agent_message_chunk", kinds)
            self.assertIn("tool_call", kinds)

            await ws.send_json({"op": "open", "id": sid})
            replayed = False
            for _ in range(12):
                msg = await ws.receive_json()
                if msg["op"] == "update" and msg.get("kind") == "agent_message_chunk":
                    replayed = True
                if msg["op"] == "opened":
                    break
            self.assertTrue(replayed)

            page = await client.get("/")
            text = await page.text()
            self.assertIn("Get sign-in link", text)
            self.assertEqual(page.status, 200)
            await ws.close()
            await app["agent"].close()
            await asyncio.to_thread(app["google"].close)


if __name__ == "__main__":
    unittest.main()
