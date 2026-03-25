from __future__ import annotations

import json
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from dashboard_app.data_access import build_dashboard_payload
from dashboard_app.runtime_manager import RuntimeManager


STATIC_DIR = Path(__file__).resolve().parent / "static"
RUNTIME_MANAGER = RuntimeManager()


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server_version = "SentinelFlowApp/1.0"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/dashboard":
            self._send_json(build_dashboard_payload(RUNTIME_MANAGER))
            return

        if parsed.path == "/":
            self._serve_static("index.html")
            return

        asset_path = parsed.path.lstrip("/")
        if asset_path in {"app.css", "app.js"}:
            self._serve_static(asset_path)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        payload = self._read_json_body()

        try:
            if parsed.path == "/api/monitor/start":
                response = RUNTIME_MANAGER.start_monitor(interface=payload.get("interface") or None)
                self._send_json(response)
                return

            if parsed.path == "/api/monitor/stop":
                response = RUNTIME_MANAGER.stop_monitor()
                self._send_json(response)
                return

            if parsed.path == "/api/analysis/start":
                dataset_path = str(payload.get("dataset_path", "")).strip()
                if not dataset_path:
                    self._send_json({"error": "dataset_path is required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                response = RUNTIME_MANAGER.start_analysis(dataset_path=dataset_path)
                self._send_json(response)
                return

            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def log_message(self, format: str, *args) -> None:
        return

    def _read_json_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            return {}
        body = self.rfile.read(content_length)
        if not body:
            return {}
        return json.loads(body.decode("utf-8"))

    def _serve_static(self, filename: str) -> None:
        path = STATIC_DIR / filename
        if not path.exists():
            self.send_error(HTTPStatus.NOT_FOUND, "Static asset not found")
            return

        content_type, _ = mimetypes.guess_type(str(path))
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type or "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(path.read_bytes())

    def _send_json(self, payload: dict | list, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = ThreadingHTTPServer((host, port), DashboardRequestHandler)
    print(f"SentinelFlow dashboard available at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down SentinelFlow dashboard...")
    finally:
        server.server_close()
