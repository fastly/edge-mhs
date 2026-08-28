#!/usr/bin/env python3
"""A throwaway local stand-in for the MHS device-metadata and driver-runtime
backends, used only by scripts/smoke-test.sh. There is no public MHS spec to
integrate against yet, so this mocks the two HTTP endpoints gateway-server's
BackendLimitsSource / FastlyBackendProxy call:

  GET  /mhs/devices/<device_id>/limits  -> DeviceLimits JSON, or 404
  POST /mhs/tool-call                   -> echoes the received body back
"""

import http.server
import json
import sys

DEVICE_LIMITS = {
    "qpcr-1": {
        "fields": {"celsius": {"kind": "range", "min": 4.0, "max": 100.0}},
    },
    "robot-arm-2": {
        "fields": {
            "axis": {"kind": "allowed", "values": ["x", "y", "z"]},
            "angle_degrees": {"kind": "range", "min": -90.0, "max": 90.0},
        },
    },
}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = self.path.strip("/").split("/")
        if len(parts) == 4 and parts[0] == "mhs" and parts[1] == "devices" and parts[3] == "limits":
            limits = DEVICE_LIMITS.get(parts[2])
            if limits is None:
                self.send_response(404)
                self.end_headers()
                return
            self._send_json(200, limits)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path == "/mhs/tool-call":
            try:
                received = json.loads(body)
            except ValueError:
                received = None
            self._send_json(200, {"status": "ok", "received": received})
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # keep smoke-test output readable


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
