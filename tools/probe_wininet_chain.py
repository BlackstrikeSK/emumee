"""Harmless host-Windows semantic probe for linked INTERNET_BUFFERSW.

Uses only a temporary 127.0.0.1 HTTP listener and literal A/B request bytes.
This is a developer probe, not part of guest execution.
"""

from __future__ import annotations

import ctypes
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from ctypes import wintypes


class InternetBuffersW(ctypes.Structure):
    pass


InternetBuffersW._fields_ = [
    ("dwStructSize", wintypes.DWORD),
    ("Next", ctypes.POINTER(InternetBuffersW)),
    ("lpcszHeader", ctypes.c_void_p),
    ("dwHeadersLength", wintypes.DWORD),
    ("dwHeadersTotal", wintypes.DWORD),
    ("lpvBuffer", ctypes.c_void_p),
    ("dwBufferLength", wintypes.DWORD),
    ("dwBufferTotal", wintypes.DWORD),
    ("dwOffsetLow", wintypes.DWORD),
    ("dwOffsetHigh", wintypes.DWORD),
]


def main() -> None:
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.connection.settimeout(3)
            expected = int(self.headers.get("Content-Length", "0"))
            body = bytearray()
            while len(body) < expected:
                try:
                    chunk = self.rfile.read1(1)
                except socket.timeout:
                    break
                if not chunk:
                    break
                body.extend(chunk)
            observed.append({"expected": expected, "body": bytes(body).decode("ascii"),
                             "tail_header": self.headers.get("X-Tail")})
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    wininet = ctypes.WinDLL("wininet", use_last_error=True)
    wininet.InternetOpenW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD,
                                     ctypes.c_wchar_p, ctypes.c_wchar_p, wintypes.DWORD]
    wininet.InternetOpenW.restype = ctypes.c_void_p
    wininet.InternetConnectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                        ctypes.c_ushort, ctypes.c_wchar_p,
                                        ctypes.c_wchar_p, wintypes.DWORD,
                                        wintypes.DWORD, ctypes.c_size_t]
    wininet.InternetConnectW.restype = ctypes.c_void_p
    wininet.HttpOpenRequestW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                         ctypes.c_wchar_p, ctypes.c_wchar_p,
                                         ctypes.c_wchar_p, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.c_size_t]
    wininet.HttpOpenRequestW.restype = ctypes.c_void_p
    wininet.HttpSendRequestExW.argtypes = [ctypes.c_void_p,
                                          ctypes.POINTER(InternetBuffersW),
                                          ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.c_size_t]
    wininet.HttpSendRequestExW.restype = wintypes.BOOL
    wininet.InternetWriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    wininet.InternetWriteFile.restype = wintypes.BOOL
    wininet.HttpEndRequestW.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       wintypes.DWORD, ctypes.c_size_t]
    wininet.HttpEndRequestW.restype = wintypes.BOOL
    wininet.InternetCloseHandle.argtypes = [ctypes.c_void_p]
    wininet.InternetCloseHandle.restype = wintypes.BOOL
    handles = []
    try:
        session = wininet.InternetOpenW("Emumee harmless probe", 1, None, None, 0)
        assert session, ctypes.get_last_error()
        handles.append(session)
        connection = wininet.InternetConnectW(session, "127.0.0.1",
                                               server.server_address[1],
                                               None, None, 3, 0, 0)
        assert connection, ctypes.get_last_error()
        handles.append(connection)
        request = wininet.HttpOpenRequestW(connection, "POST", "/probe",
                                            None, None, None, 0, 0)
        assert request, ctypes.get_last_error()
        handles.append(request)
        a = ctypes.create_string_buffer(b"A")
        b = ctypes.create_string_buffer(b"B")
        tail_header = ctypes.create_unicode_buffer("X-Tail: second\r\n")
        second = InternetBuffersW()
        second.dwStructSize = ctypes.sizeof(second)
        second.lpcszHeader = ctypes.addressof(tail_header)
        second.dwHeadersLength = len("X-Tail: second\r\n")
        second.lpvBuffer = ctypes.addressof(b)
        second.dwBufferLength = 1
        second.dwBufferTotal = int(sys.argv[1]) if len(sys.argv) > 1 else 0
        first = InternetBuffersW()
        first.dwStructSize = ctypes.sizeof(first)
        first.Next = ctypes.pointer(second)
        first.lpvBuffer = ctypes.addressof(a)
        first.dwBufferLength = 1
        first.dwBufferTotal = 2
        sent = bool(wininet.HttpSendRequestExW(request, ctypes.byref(first), None, 0, 0))
        send_error = ctypes.get_last_error()
        written = wintypes.DWORD()
        wrote = None
        if sent and "--write" in sys.argv:
            wrote = bool(wininet.InternetWriteFile(request, ctypes.addressof(b), 1,
                                                    ctypes.byref(written)))
        ended = bool(wininet.HttpEndRequestW(request, None, 0, 0)) if sent else False
        end_error = ctypes.get_last_error()
        print(json.dumps({"sent": sent, "send_error": send_error,
                          "wrote": wrote, "written": written.value,
                          "ended": ended, "end_error": end_error,
                          "observed": observed}))
    finally:
        for handle in reversed(handles):
            wininet.InternetCloseHandle(handle)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    main()
