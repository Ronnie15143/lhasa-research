#!/usr/bin/env python3
"""mcp_probe.py - speak just enough MCP over stdio to list a server's tools.

usage: mcp_probe.py <exe> [args...] [--call NAME JSON]

The Codex install registers `reverse-skill` as
  <...>\\wujin-launcher.exe --mcp-server
so before wiring it into anything we want to know exactly what it exposes.
"""
import json
import queue
import subprocess
import sys
import threading
import time


def reader(stream, q):
    for line in iter(stream.readline, b''):
        q.put(line)
    q.put(None)


def send(proc, obj):
    data = (json.dumps(obj) + "\n").encode()
    proc.stdin.write(data)
    proc.stdin.flush()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    call = None
    args = sys.argv[1:]
    if "--call" in args:
        i = args.index("--call")
        call = (args[i + 1], json.loads(args[i + 2]))
        args = args[:i]

    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, bufsize=0)
    q = queue.Queue()
    threading.Thread(target=reader, args=(proc.stdout, q), daemon=True).start()

    def collect(seconds):
        out = []
        end = time.time() + seconds
        while time.time() < end:
            try:
                item = q.get(timeout=0.2)
            except queue.Empty:
                continue
            if item is None:
                break
            out.append(item.decode(errors='replace').strip())
        return out

    send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                           "clientInfo": {"name": "dsh-probe", "version": "0.1"}}})
    for line in collect(6):
        print("INIT>", line[:800])
    send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    time.sleep(0.3)

    send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    for line in collect(6):
        print("TOOLS>", line[:4000])

    if call:
        name, arguments = call
        send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": name, "arguments": arguments}})
        for line in collect(30):
            print("CALL>", line[:2000])

    try:
        proc.terminate()
    except Exception:
        pass
    err = proc.stderr.read(2000) if proc.stderr else b''
    if err:
        print("STDERR>", err.decode(errors='replace')[:1500])
    return 0


if __name__ == '__main__':
    sys.exit(main())
