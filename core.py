from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import urllib.parse
from pathlib import Path
from typing import Iterable


LOCAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".lan",
    ".lab",
    ".test",
    ".internal",
    ".home.arpa",
)

SENSITIVE_FLAGS = {
    "--cookies",
    "--headers",
    "--blind-oob-secret",
    "--api-key",
}


class ScopeError(ValueError):
    pass


def is_allowed_host(host: str) -> bool:
    normalized = host.strip().strip("[]").rstrip(".").lower()
    if not normalized:
        return False
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    if normalized.endswith(LOCAL_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return bool(address.is_loopback or address.is_private or address.is_link_local)


def validate_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ScopeError("目标 URL 不能为空")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ScopeError("目标必须使用 http:// 或 https://")
    if not parsed.hostname:
        raise ScopeError(f"无法从目标中解析主机名：{value}")
    if not is_allowed_host(parsed.hostname):
        raise ScopeError(
            f"目标超出本地实验范围：{parsed.hostname}\n"
            "只允许 localhost、回环地址、RFC1918/链路本地地址，"
            "以及 .local/.lan/.lab/.test/.internal/.home.arpa 域名。"
        )
    return value


def _read_text_limited(path: Path, limit: int = 10 * 1024 * 1024) -> str:
    size = path.stat().st_size
    if size > limit:
        raise ScopeError(f"输入文件过大（{size} bytes），上限为 {limit} bytes")
    return path.read_text(encoding="utf-8", errors="replace")


def _targets_from_text(text: str) -> list[str]:
    targets: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line.split()[0])
    return targets


def _targets_from_raw_http(text: str) -> list[str]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            candidate = parts[1]
            if candidate.lower().startswith(("http://", "https://")):
                return [candidate]
        raise ScopeError("raw-http 文件首行必须是 METHOD http(s)://host/path HTTP/...")
    raise ScopeError("raw-http 文件为空")


def _targets_from_har(path: Path) -> list[str]:
    try:
        document = json.loads(_read_text_limited(path))
    except json.JSONDecodeError as exc:
        raise ScopeError(f"HAR JSON 解析失败：{exc}") from exc
    entries = document.get("log", {}).get("entries", [])
    targets = [
        entry.get("request", {}).get("url", "")
        for entry in entries
        if isinstance(entry, dict)
    ]
    return [target for target in targets if target]


def validate_target_input(target: str, input_type: str = "auto") -> list[str]:
    target = target.strip()
    if not target:
        raise ScopeError("请先输入目标 URL 或选择目标文件")

    path = Path(target)
    is_file = path.is_file()
    kind = input_type.lower()

    if kind == "url" or (kind == "auto" and not is_file):
        candidates = [
            item.strip()
            for item in target.replace(";", "\n").splitlines()
            if item.strip()
        ]
    elif kind in {"file", "auto", "raw-http", "har"}:
        if not is_file:
            raise ScopeError(f"目标文件不存在：{target}")
        if kind == "har":
            candidates = _targets_from_har(path)
        else:
            text = _read_text_limited(path)
            candidates = (
                _targets_from_raw_http(text)
                if kind == "raw-http"
                else _targets_from_text(text)
            )
    else:
        raise ScopeError(f"不支持的输入类型：{input_type}")

    if not candidates:
        raise ScopeError("没有找到可扫描的目标")

    validated = [validate_url(candidate) for candidate in candidates]
    if len(validated) > 5000:
        raise ScopeError("单次目标数量超过 5000，请拆分文件后再运行")
    return validated


def validate_optional_url(value: str, name: str) -> None:
    if value.strip():
        try:
            validate_url(value)
        except ScopeError as exc:
            raise ScopeError(f"{name} 超出范围：{exc}") from exc


def split_multiline(value: str) -> list[str]:
    return [
        line.strip()
        for line in value.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def redact_command(args: Iterable[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            redacted.append("<已脱敏>")
            redact_next = False
            continue
        if arg in SENSITIVE_FLAGS:
            redacted.append(arg)
            redact_next = True
            continue
        if any(arg.startswith(f"{flag}=") for flag in SENSITIVE_FLAGS):
            redacted.append(f"{arg.split('=', 1)[0]}=<已脱敏>")
            continue
        redacted.append(arg)
    return redacted


def command_to_text(args: Iterable[str]) -> str:
    values = [str(arg) for arg in args]
    if os.name == "nt":
        return subprocess.list2cmdline(values)
    return subprocess.list2cmdline(values)


def preview_command(args: Iterable[str]) -> str:
    return command_to_text(redact_command(args))
