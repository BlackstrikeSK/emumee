"""Strict, byte-exact HTTP request/response fixtures for the network broker."""

from __future__ import annotations

import base64
import binascii
import json
from urllib.parse import urlsplit


MAX_FIXTURE_FILE = 48 * 1024 * 1024
MAX_FIXTURE_BYTES = 32 * 1024 * 1024
MAX_BODY = 16 * 1024 * 1024
MAX_RULES = 32


def _body(value: dict) -> bytes:
    choices = [key for key in ("body_base64", "body_utf8") if key in value]
    if len(choices) != 1:
        raise ValueError("Exactly one body_base64 or body_utf8 field is required")
    if choices[0] == "body_utf8":
        if not isinstance(value["body_utf8"], str):
            raise ValueError("body_utf8 must be a string")
        data = value["body_utf8"].encode("utf-8")
    else:
        encoded = value["body_base64"]
        if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_BODY + 2) // 3):
            raise ValueError("Invalid or oversized body_base64")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Invalid body_base64") from exc
        if base64.b64encode(data).decode("ascii") != encoded:
            raise ValueError("body_base64 must use canonical encoding")
    if len(data) > MAX_BODY:
        raise ValueError("HTTP fixture body exceeds 16 MiB")
    return data


def _headers(value: dict | list, *, response: bool):
    pairs = list(value.items()) if isinstance(value, dict) else value
    if not isinstance(pairs, list) or len(pairs) > 64:
        raise ValueError("HTTP fixture headers must contain at most 64 entries")
    if any(not isinstance(pair, (list, tuple)) or len(pair) != 2 or
           not all(isinstance(part, str) for part in pair) or
           not pair[0] or any(char in pair[0] + pair[1] for char in "\r\n\0")
           for pair in pairs):
        raise ValueError("Invalid HTTP fixture header")
    if sum(len(name) + len(value) for name, value in pairs) > 16 * 1024:
        raise ValueError("HTTP fixture headers exceed 16 KiB")
    if response:
        return [[name, value] for name, value in pairs]
    lowered = [name.casefold() for name, _ in pairs]
    if len(lowered) != len(set(lowered)):
        raise ValueError("Duplicate request header name")
    return {name.casefold(): value for name, value in pairs}


def parse_network_fixtures(raw: bytes) -> list[dict]:
    """Validate and normalize fixtures; private decoded bytes stay in the broker."""
    if len(raw) > MAX_FIXTURE_FILE:
        raise ValueError("HTTP fixture file exceeds 48 MiB")
    try:
        document = json.loads(raw)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("Invalid HTTP fixture JSON") from exc
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("HTTP fixture version must be 1")
    rules = document.get("rules")
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError("HTTP fixture rules must be a list of at most 32 entries")
    result: list[dict] = []
    total_bytes = 0
    seen: set[tuple] = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict) or not isinstance(rule.get("request"), dict) or not isinstance(rule.get("response"), dict):
            raise ValueError(f"Invalid HTTP fixture rule {index}")
        ident = rule.get("id", f"rule-{index + 1}")
        req, resp = rule["request"], rule["response"]
        method, url, chunked = req.get("method"), req.get("url"), req.get("chunked")
        if (not isinstance(ident, str) or not 0 < len(ident) <= 64 or
                not isinstance(method, str) or method not in
                {"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH"} or
                not isinstance(url, str) or not 0 < len(url) <= 2048 or
                type(chunked) is not bool):
            raise ValueError(f"Invalid HTTP fixture request {index}")
        try:
            parts = urlsplit(url)
            if parts.scheme not in {"http", "https"} or not parts.hostname or parts.port is None and ":" in parts.netloc.split("]")[-1]:
                raise ValueError("Invalid HTTP fixture URL")
        except ValueError as exc:
            raise ValueError(f"Invalid HTTP fixture URL in rule {index}") from exc
        request_headers = _headers(req.get("headers"), response=False)
        request_body = _body(req)
        status, reason, version = resp.get("status"), resp.get("reason"), resp.get("version")
        if (type(status) is not int or not 100 <= status <= 999 or
                not isinstance(reason, str) or len(reason) > 128 or
                any(char in reason for char in "\r\n\0") or
                version not in {"HTTP/1.0", "HTTP/1.1"}):
            raise ValueError(f"Invalid HTTP fixture response {index}")
        response_headers = _headers(resp.get("headers"), response=True)
        response_body = _body(resp)
        total_bytes += len(request_body) + len(response_body)
        if total_bytes > MAX_FIXTURE_BYTES:
            raise ValueError("HTTP fixture bodies exceed 32 MiB total")
        key = (method, url, chunked, tuple(sorted(request_headers.items())), request_body)
        if key in seen:
            raise ValueError("Duplicate exact HTTP fixture request")
        seen.add(key)
        result.append({"id": ident, "request": {"method": method, "url": url,
                                                  "chunked": chunked,
                                                  "headers": request_headers,
                                                  "body_base64": base64.b64encode(request_body).decode("ascii")},
                       "response": {"status": status, "reason": reason, "version": version,
                                    "headers": response_headers,
                                    "body_base64": base64.b64encode(response_body).decode("ascii")},
                       "request_body": request_body, "response_body": response_body})
    return result


def public_fixture_document(rules: list[dict]) -> bytes:
    return json.dumps({"version": 1, "rules": [
        {"id": rule["id"], "request": rule["request"], "response": rule["response"]}
        for rule in rules]}, indent=2).encode("utf-8")


def matching_fixture(rules: list[dict], method: str, url: str, chunked: bool,
                     headers: dict[str, str], body: bytes) -> dict | None:
    normalized = _headers(headers, response=False)
    for rule in rules:
        expected = rule["request"]
        if (expected["method"] == method and expected["url"] == url and
                expected["chunked"] == chunked and expected["headers"] == normalized and
                rule["request_body"] == body):
            return rule
    return None
