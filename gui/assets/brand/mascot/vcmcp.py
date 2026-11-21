"""Tiny stdio MCP client for `vectorcraft-cli mcp --headless`, confined to this folder."""
import json, os, subprocess, base64

CLI = os.environ.get("VECTORCRAFT_CLI", r"D:\Tools\vectorcraft\vectorcraft-0.24.1-windows-x64-portable\vectorcraft-cli.exe")
HERE = os.path.dirname(os.path.abspath(__file__))


class VC:
    def __init__(self):
        self.p = subprocess.Popen([CLI, "mcp", "--headless", "--automation-read-root", HERE, "--automation-write-root", HERE],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, encoding="utf-8", bufsize=1)
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "vc", "version": "1"}})
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")

    def rpc(self, method, params):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n")
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("server exited")
            msg = json.loads(line)
            if msg.get("id") == self.n:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg["result"]

    def tool(self, name, **args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        texts = [c.get("text", "") for c in r.get("content", []) if c.get("type") == "text"]
        imgs = [c["data"] for c in r.get("content", []) if c.get("type") == "image"]
        if r.get("isError"):
            raise RuntimeError(f"{name} {json.dumps(args)[:300]}: {' '.join(texts)[:600]}")
        out = texts[0] if texts else ""
        try:
            out = json.loads(out)
        except Exception:
            pass
        return (out, imgs) if imgs else out

    def run(self, command, **params):
        return self.tool("command_run", id=command, params=params)

    def preview(self, path, max_side=512):
        _, imgs = self.tool("render_preview", max_side=max_side)
        open(path, "wb").write(base64.b64decode(imgs[0]))

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)
