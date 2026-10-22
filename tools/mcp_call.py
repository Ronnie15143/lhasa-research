#!/usr/bin/env python3
"""mcp_call.py - drive a stdio MCP server: initialize, then run a list of calls,
and dump every response to a UTF-8 file (console encoding mangles CJK).

usage: mcp_call.py <out.json> <exe> [args...] -- <tool> <json-args> [-- <tool> <json> ...]
       mcp_call.py out.json exe --mcp-server -- list_skills '{}' -- detect_tools '{}'
"""
import json, os
import queue
import subprocess
import sys
import threading
import time


def reader(stream, q):
    for line in iter(stream.readline, b''):
        q.put(line)
    q.put(None)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    out_path = sys.argv[1]
    rest = sys.argv[2:]
    if "--" not in rest:
        print("need -- separator before calls")
        return 2
    i = rest.index("--")
    cmd = rest[:i]
    calls = []
    cur = rest[i + 1:]
    while cur:
        if "--" in cur:
            j = cur.index("--")
            calls.append((cur[0], json.loads(cur[1]) if len(cur) > 1 else {}))
            cur = cur[j + 1:]
        else:
            calls.append((cur[0], json.loads(cur[1]) if len(cur) > 1 else {}))
            cur = []

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, bufsize=0)
    q = queue.Queue()
    threading.Thread(target=reader, args=(proc.stdout, q), daemon=True).start()

    results = []

    def pump(seconds):
        end = time.time() + seconds
        got = []
        while time.time() < end:
            try:
                item = q.get(timeout=0.2)
            except queue.Empty:
                continue
            if item is None:
                break
            got.append(item.decode('utf-8', 'replace').strip())
        return got

    proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                  "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                             "clientInfo": {"name": "dsh", "version": "0.1"}}}) + "\n").encode())
    proc.stdin.flush()
    results.append({"step": "initialize", "lines": pump(float(os.environ.get("MCP_INIT_WAIT", "5")))})
    proc.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode())
    proc.stdin.flush()
    time.sleep(0.3)

    rid = 10
    for name, arguments in calls:
        rid += 1
        req = {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
        proc.stdin.write((json.dumps(req) + "\n").encode())
        proc.stdin.flush()
        results.append({"step": name, "args": arguments, "lines": pump(float(os.environ.get("MCP_WAIT", "12")))})

    try:
        proc.terminate()
    except Exception:
        pass

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
    print(f"wrote {out_path} ({len(results)} steps)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
