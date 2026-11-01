from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import (
    ScopeError,
    preview_command,
    split_multiline,
    validate_optional_url,
    validate_target_input,
    validate_url,
)


APP_DIR = Path(__file__).resolve().parent
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
LOCAL_CONFIG = APP_DIR / "config.local.json"


def _load_local_config() -> dict[str, str]:
    if not LOCAL_CONFIG.is_file():
        return {}
    try:
        data = json.loads(LOCAL_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


LOCAL_SETTINGS = _load_local_config()


def _resolve_dalfox() -> Path:
    for candidate in (
        os.environ.get("DALFOX_EXE", ""),
        str(LOCAL_SETTINGS.get("dalfox_exe", "")),
    ):
        if candidate:
            path = Path(candidate).expanduser()
            if path.is_file():
                return path
    discovered = shutil.which("dalfox") or shutil.which("dalfox.exe")
    if discovered:
        return Path(discovered)
    for path in (
        APP_DIR / "dalfox.exe",
        APP_DIR.parent / "dalfox" / "dalfox.exe",
    ):
        if path.is_file():
            return path
    return APP_DIR / "dalfox.exe"


def _resolve_output_dir() -> Path:
    for candidate in (
        os.environ.get("DALFOX_GUI_OUTPUT", ""),
        str(LOCAL_SETTINGS.get("output_dir", "")),
    ):
        if candidate:
            return Path(candidate).expanduser().resolve()
    base = Path(os.environ.get("LOCALAPPDATA", Path.home()))
    return base / "DalfoxGUI" / "output"


DALFOX = _resolve_dalfox()
OUTPUT_DIR = _resolve_output_dir()

COLORS = {
    "bg": "#08111f",
    "panel": "#101c2e",
    "panel_alt": "#14243a",
    "text": "#e8f3ff",
    "muted": "#8aa4c1",
    "accent": "#22d3ee",
    "accent_dark": "#0891b2",
    "warning": "#ffd166",
    "danger": "#ef4444",
    "success": "#34d399",
}

PAYLOAD_SELECTORS = {
    "javascript": {
        "label": "JavaScript 执行 Payload（新手推荐）",
        "description": (
            "列出常见的 JavaScript 执行 Payload，适合了解基础脚本上下文、"
            "关键字拆分和反引号等写法。\n"
            "用途：学习常用执行向量，或为自定义 Payload 提供参考。\n"
            "是否联网：否。结果会显示在下方“实时输出”中。"
        ),
    },
    "event-handlers": {
        "label": "DOM 事件处理器列表",
        "description": (
            "列出 onclick、onmouseover 等浏览器事件属性名称。\n"
            "用途：检查目标允许哪些事件属性，辅助构造上下文相关测试项。\n"
            "是否联网：否。"
        ),
    },
    "useful-tags": {
        "label": "常用 HTML 标签列表",
        "description": (
            "列出 script、img、svg 等常用于 XSS 测试的 HTML 标签。\n"
            "用途：了解不同标签的测试面，不会自动向任何网站发请求。\n"
            "是否联网：否。"
        ),
    },
    "payloadbox": {
        "label": "PayloadBox 在线 Payload 库",
        "description": (
            "从 PayloadBox 在线资源获取 Payload。\n"
            "用途：需要更丰富的外部 Payload 集合时使用。\n"
            "是否联网：是。只下载 Payload 文本，不扫描目标。"
        ),
    },
    "portswigger": {
        "label": "PortSwigger 在线 Payload 库",
        "description": (
            "从 PortSwigger 在线资源获取 XSS Payload。\n"
            "用途：查看官方研究资料中的常用测试向量。\n"
            "是否联网：是。只下载 Payload 文本，不扫描目标。"
        ),
    },
    "uri-scheme": {
        "label": "URI 协议 Payload",
        "description": (
            "列出 javascript:、data: 等 URI 协议形式的 Payload。\n"
            "用途：测试链接、跳转、iframe 或属性上下文。\n"
            "是否联网：否。"
        ),
    },
    "special-chars": {
        "label": "上下文探测特殊字符",
        "description": (
            "列出特殊字符及其编码形式。\n"
            "用途：分析 HTML 属性、引号、尖括号或编码过滤情况。\n"
            "是否联网：否。"
        ),
    },
    "functions": {
        "label": "确认函数与可执行 Sink",
        "description": (
            "列出可肉眼确认执行结果的函数和可执行点。\n"
            "用途：需要观察弹窗或确认执行效果时使用。\n"
            "是否联网：否。"
        ),
    },
    "awesome-alert": {
        "label": "演示用 Alert Payload",
        "description": (
            "列出适合教学演示和截图的 alert 类 Payload。\n"
            "用途：本地靶场演示，不建议用于真实业务破坏性测试。\n"
            "是否联网：否。"
        ),
    },
    "dom-clobbering": {
        "label": "DOM Clobbering Payload",
        "description": (
            "列出 DOM Clobbering 相关 Payload。\n"
            "用途：研究 HTML 命名元素覆盖 JavaScript 对象的情况。\n"
            "是否联网：否。"
        ),
    },
    "mxss": {
        "label": "Mutation XSS / Sanitizer Bypass",
        "description": (
            "列出 Mutation XSS 和 HTML Sanitizer 绕过相关 Payload。\n"
            "用途：高级 HTML 过滤和净化器研究。\n"
            "是否联网：否。仅在明确授权的靶场中使用。"
        ),
    },
    "blind": {
        "label": "盲 XSS 模板",
        "description": (
            "列出盲 XSS 基础模板，其中回调地址需要替换。\n"
            "用途：研究异步触发和带外确认。\n"
            "是否联网：查看模板本身不联网；实际扫描盲 XSS 需要回调服务。"
        ),
    },
    "all": {
        "label": "全部本地 Payload 资源",
        "description": (
            "一次列出 Dalfox 内置的全部本地资源，不访问远程库。\n"
            "用途：想一次查看所有分类时使用，输出会比较长。\n"
            "是否联网：否。"
        ),
    },
}

PAYLOAD_LABEL_TO_KEY = {
    item["label"]: key for key, item in PAYLOAD_SELECTORS.items()
}


class ScrollableFrame(ttk.Frame):
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(
            self, orient="vertical", command=self.canvas.yview
        )
        self.inner = ttk.Frame(self.canvas)
        self.window_id = self.canvas.create_window(
            (0, 0), window=self.inner, anchor="nw"
        )
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.canvas.bind("<Enter>", self._bind_mousewheel)
        self.canvas.bind("<Leave>", self._unbind_mousewheel)

    def _on_inner_configure(self, _event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event: tk.Event) -> None:
        self.canvas.itemconfigure(self.window_id, width=event.width)

    def _bind_mousewheel(self, _event: tk.Event) -> None:
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_mousewheel(self, _event: tk.Event) -> None:
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event: tk.Event) -> None:
        self.canvas.yview_scroll(int(-event.delta / 120), "units")


class DalfoxGui(tk.Tk):
    def __init__(self, start_hidden: bool = False) -> None:
        super().__init__()
        if start_hidden:
            self.withdraw()
        self.title("Dalfox GUI 3.2.4")
        self.geometry("1320x900")
        self.minsize(1120, 760)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self.vars: dict[str, tk.StringVar] = {}
        self.bool_vars: dict[str, tk.BooleanVar] = {}
        self.encoder_vars: dict[str, tk.BooleanVar] = {}
        self.text_widgets: dict[str, tk.Text] = {}
        self.process: subprocess.Popen[str] | None = None
        self.reader_thread: threading.Thread | None = None
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.preview_after_id: str | None = None
        self.running_mode = ""
        self.help_panel_count = 0

        self._configure_style()
        self._build_header()
        self._build_body()
        self._build_footer()
        self._bind_preview_updates()
        self.after(120, self._drain_events)
        self._refresh_preview()
        self._update_payload_description()

        if not DALFOX.is_file():
            self.after(
                100,
                lambda: messagebox.showerror(
                    "Dalfox 不存在",
                    f"未找到 Dalfox：\n{DALFOX}\n\n请先确认安装路径。",
                ),
            )

    def _configure_style(self) -> None:
        self.configure(bg=COLORS["bg"])
        style = ttk.Style(self)
        style.theme_use("clam")
        self.option_add("*Font", ("Microsoft YaHei UI", 10))
        style.configure(
            ".",
            background=COLORS["panel"],
            foreground=COLORS["text"],
            fieldbackground="#0c1828",
            bordercolor="#29405d",
            lightcolor="#29405d",
            darkcolor="#29405d",
        )
        style.configure("TFrame", background=COLORS["panel"])
        style.configure("TLabel", background=COLORS["panel"], foreground=COLORS["text"])
        style.configure(
            "Muted.TLabel", foreground=COLORS["muted"], background=COLORS["panel"]
        )
        style.configure(
            "Header.TLabel",
            font=("Microsoft YaHei UI", 22, "bold"),
            foreground=COLORS["text"],
            background=COLORS["bg"],
        )
        style.configure(
            "Subheader.TLabel",
            foreground=COLORS["muted"],
            background=COLORS["bg"],
        )
        style.configure(
            "TLabelframe",
            background=COLORS["panel"],
            bordercolor="#29405d",
            relief="solid",
        )
        style.configure(
            "TLabelframe.Label",
            background=COLORS["panel"],
            foreground=COLORS["accent"],
            font=("Microsoft YaHei UI", 10, "bold"),
        )
        style.configure(
            "TNotebook", background=COLORS["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0)
        )
        style.configure(
            "TNotebook.Tab",
            background="#0d1929",
            foreground=COLORS["muted"],
            padding=(18, 9),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", COLORS["panel_alt"])],
            foreground=[("selected", COLORS["text"])],
        )
        style.configure(
            "TButton",
            background="#19314c",
            foreground=COLORS["text"],
            padding=(12, 7),
        )
        style.map("TButton", background=[("active", "#234566")])
        style.configure(
            "Accent.TButton",
            background=COLORS["accent_dark"],
            foreground="white",
            font=("Microsoft YaHei UI", 10, "bold"),
        )
        style.map("Accent.TButton", background=[("active", "#06b6d4")])
        style.configure(
            "Danger.TButton", background="#991b1b", foreground="white"
        )
        style.map("Danger.TButton", background=[("active", "#dc2626")])
        style.configure(
            "Warning.TLabel",
            foreground=COLORS["warning"],
            background=COLORS["panel"],
        )
        style.configure(
            "Success.TLabel",
            foreground=COLORS["success"],
            background=COLORS["panel"],
        )
        style.configure(
            "TEntry",
            fieldbackground="#0c1828",
            foreground=COLORS["text"],
            insertcolor=COLORS["text"],
        )
        style.configure(
            "TCombobox",
            fieldbackground="#0c1828",
            foreground=COLORS["text"],
            arrowcolor=COLORS["text"],
        )
        style.configure(
            "TCheckbutton",
            background=COLORS["panel"],
            foreground=COLORS["text"],
        )
        style.map("TCheckbutton", background=[("active", COLORS["panel"])])
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor="#0b1727",
            background=COLORS["accent"],
        )

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=COLORS["bg"], padx=22, pady=14)
        header.pack(fill="x")
        title_box = tk.Frame(header, bg=COLORS["bg"])
        title_box.pack(side="left", fill="x", expand=True)
        ttk.Label(
            title_box, text="DALFOX 图形控制台", style="Header.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            title_box,
            text="XSS 扫描、Payload 查询与本地 API | 只允许回环、内网和本地实验域名",
            style="Subheader.TLabel",
        ).pack(anchor="w", pady=(3, 0))
        self.version_badge = tk.Label(
            header,
            text="v3.2.4",
            bg="#10243b",
            fg=COLORS["accent"],
            padx=14,
            pady=8,
            font=("Microsoft YaHei UI", 11, "bold"),
        )
        self.version_badge.pack(side="right")

    def _build_body(self) -> None:
        body = ttk.Panedwindow(self, orient="vertical")
        body.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        top = ttk.Frame(body)
        bottom = ttk.Frame(body)
        body.add(top, weight=4)
        body.add(bottom, weight=2)

        self.notebook = ttk.Notebook(top)
        self.notebook.pack(fill="both", expand=True)
        self.notebook.bind("<<NotebookTabChanged>>", lambda _event: self._refresh_preview())

        self.scan_tab = ttk.Frame(self.notebook)
        self.payload_tab = ttk.Frame(self.notebook)
        self.server_tab = ttk.Frame(self.notebook)
        self.mcp_tab = ttk.Frame(self.notebook)
        self.presets_tab = ttk.Frame(self.notebook)
        self.about_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.scan_tab, text="扫描")
        self.notebook.add(self.payload_tab, text="Payload 查询")
        self.notebook.add(self.server_tab, text="本地 API 服务")
        self.notebook.add(self.mcp_tab, text="MCP 接口")
        self.notebook.add(self.presets_tab, text="新手预设")
        self.notebook.add(self.about_tab, text="说明与安全边界")

        self._build_scan_tab()
        self._build_payload_tab()
        self._build_server_tab()
        self._build_mcp_tab()
        self._build_presets_tab()
        self._build_about_tab()
        self._build_console(bottom)

    def _build_scan_tab(self) -> None:
        outer = ttk.Frame(self.scan_tab, padding=10)
        outer.pack(fill="both", expand=True)

        target_box = ttk.LabelFrame(outer, text="扫描目标", padding=10)
        target_box.pack(fill="x")
        target_box.columnconfigure(1, weight=1)

        ttk.Label(target_box, text="目标 URL / 文件").grid(
            row=0, column=0, sticky="w", padx=(0, 8)
        )
        ttk.Entry(target_box, textvariable=self.sv("target")).grid(
            row=0, column=1, sticky="ew"
        )
        ttk.Button(target_box, text="选择文件", command=self._choose_target_file).grid(
            row=0, column=2, padx=(8, 0)
        )
        ttk.Label(
            target_box,
            text="例：http://127.0.0.1:8080/?q=FUZZ",
            style="Muted.TLabel",
        ).grid(row=1, column=1, sticky="w", pady=(4, 0))

        self.auth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            target_box,
            text="我确认已获得目标所有者的明确授权，且目标属于本地/内网实验环境",
            variable=self.auth_var,
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))

        preset_bar = ttk.Frame(target_box)
        preset_bar.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Label(preset_bar, text="一键配置：", style="Muted.TLabel").pack(
            side="left"
        )
        for label, name in (
            ("本机预检", "dry_run"),
            ("标准扫描", "standard"),
            ("深度扫描", "deep"),
            ("仅参数发现", "discovery"),
            ("存储型 XSS", "stored"),
        ):
            ttk.Button(
                preset_bar,
                text=label,
                command=lambda value=name: self._apply_scan_preset(value),
            ).pack(side="left", padx=(6, 0))

        self._help_panel(
            outer,
            "扫描页怎么用",
            (
                "推荐顺序：填写目标 → 选择顶部预设 → 勾选授权 → "
                "先点“安全检查 / Dry Run” → 确认请求量后再“开始扫描”。\n"
                "结果会显示在窗口下方；真实扫描会向目标发送 HTTP 请求。"
            ),
        )

        nested = ttk.Notebook(outer)
        nested.pack(fill="both", expand=True, pady=(10, 0))
        self.scan_options_notebook = nested

        basics = ScrollableFrame(nested)
        requests = ScrollableFrame(nested)
        discovery = ScrollableFrame(nested)
        xss = ScrollableFrame(nested)
        waf = ScrollableFrame(nested)
        output = ScrollableFrame(nested)
        for tab, text in (
            (basics, "基础与性能"),
            (requests, "请求与鉴权"),
            (discovery, "发现与范围"),
            (xss, "XSS 引擎"),
            (waf, "WAF 与高级"),
            (output, "输出与报告"),
        ):
            nested.add(tab, text=text)

        self._build_scan_basics(basics.inner)
        self._build_scan_request(requests.inner)
        self._build_scan_discovery(discovery.inner)
        self._build_scan_xss(xss.inner)
        self._build_scan_waf(waf.inner)
        self._build_scan_output(output.inner)

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(
            actions,
            text="安全检查 / Dry Run",
            command=self._start_dry_run,
        ).pack(side="left")
        ttk.Button(
            actions,
            text="开始扫描",
            style="Accent.TButton",
            command=self._start_scan,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions,
            text="停止",
            style="Danger.TButton",
            command=self._stop_process,
        ).pack(side="left", padx=(8, 0))
        ttk.Label(
            actions,
            text="不会把公网目标交给 Dalfox",
            style="Warning.TLabel",
        ).pack(side="right")

    def _build_scan_basics(self, parent: ttk.Frame) -> None:
        self._help_panel(
            parent,
            "这一页控制什么",
            (
                "控制输入方式、并发、超时、限速和运行模式。新手建议先保留默认值，"
                "只使用“本机预检”或“标准扫描”预设；workers 和 rate-limit 越大，"
                "请求量越高。Dry Run 只分析目标与参数，不发送攻击 Payload。"
            ),
        )
        input_group = self._group(parent, "输入")
        self._combo(
            input_group,
            0,
            "输入类型",
            "input_type",
            ("auto", "url", "file", "raw-http", "har"),
            "auto",
        )
        self._combo(
            input_group,
            1,
            "URL 去重",
            "dedup_urls",
            ("exact", "signature", "off"),
            "exact",
        )
        self._path(
            input_group, 2, "断点状态文件", "state_file", save=True
        )
        self._path(input_group, 3, "配置文件", "config", save=False)

        mode_group = self._group(parent, "运行模式")
        self._check(mode_group, 0, "Dry Run：只做预检，不发送攻击 Payload", "dry_run")
        self._check(
            mode_group, 1, "发现到结果时实时流式输出", "stream_findings"
        )
        self._check(mode_group, 2, "静默模式（只保留 POC 输出）", "silence")
        self._check(mode_group, 3, "调试日志", "debug")
        self._check(mode_group, 4, "关闭终端颜色（推荐）", "no_color", True)

        perf_group = self._group(parent, "性能与超时")
        self._entry(perf_group, 0, "并发 workers", "workers", "10")
        self._entry(
            perf_group, 1, "同时目标数", "max_concurrent_targets", "1"
        )
        self._entry(
            perf_group, 2, "每主机目标上限", "max_targets_per_host", "100"
        )
        self._entry(perf_group, 3, "单请求超时（秒）", "timeout", "10")
        self._entry(
            perf_group, 4, "单目标扫描时限（秒，0=不限）", "scan_timeout", "300"
        )
        self._entry(perf_group, 5, "请求间隔（毫秒）", "delay", "50")
        self._entry(perf_group, 6, "全局限速（请求/秒，0=不限）", "rate_limit", "10")
        self._entry(perf_group, 7, "失败重试次数", "retries", "1")
        self._entry(perf_group, 8, "重试基础等待（毫秒）", "retry_delay", "1000")

    def _build_scan_request(self, parent: ttk.Frame) -> None:
        self._help_panel(
            parent,
            "什么时候需要这一页",
            (
                "普通 URL 扫描保持 GET 即可。测试登录后的页面时，可以填写 Cookie、"
                "Authorization Header 或 raw HTTP 文件；请求体和参数用于 POST/API 场景。"
                "Cookie、Header 和 Secret 在命令预览中会自动脱敏。"
            ),
        )
        request_group = self._group(parent, "HTTP 请求")
        self._combo(
            request_group,
            0,
            "HTTP 方法",
            "method",
            ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"),
            "GET",
        )
        self._entry(request_group, 1, "请求体 data", "data")
        self._text(
            request_group,
            2,
            "Headers（每行一个，如 X-Test: 1）",
            "headers",
            3,
        )
        self._text(
            request_group,
            3,
            "Cookies（每行一个；预览会脱敏）",
            "cookies",
            2,
        )
        self._entry(request_group, 4, "User-Agent", "user_agent")
        self._path(
            request_group, 5, "从 raw HTTP 读取 Cookie", "cookie_from_raw"
        )
        self._entry(
            request_group, 6, "指定参数（每行/逗号分隔）", "param"
        )
        self._entry(request_group, 7, "忽略参数（每行/逗号分隔）", "ignore_param")

        session_group = self._group(parent, "会话检测")
        self._entry(session_group, 0, "会话有效正则", "session_check")
        self._entry(
            session_group, 1, "会话检测 URL（仅本地范围）", "session_check_url"
        )
        self._combo(
            session_group,
            2,
            "会话失效策略",
            "on_session_loss",
            ("abort", "continue"),
            "abort",
        )

        network_group = self._group(parent, "网络")
        self._entry(network_group, 0, "代理 URL", "proxy")
        self._combo(
            network_group,
            1,
            "TLS 校验",
            "insecure",
            ("默认", "开启 --insecure", "关闭 --insecure=false"),
            "默认",
        )
        self._check(network_group, 2, "跟随 HTTP 重定向", "follow_redirects")
        self._entry(
            network_group, 3, "忽略状态码（逗号分隔）", "ignore_return"
        )

    def _build_scan_discovery(self, parent: ttk.Frame) -> None:
        self._help_panel(
            parent,
            "参数发现与范围过滤",
            (
                "参数发现会从页面、表单和 URL 中寻找可测试参数；参数挖掘会使用"
                "字典或远程词表继续扩充分析。只想查看参数时选择“只做参数发现”。"
                "URL/域名过滤用于把测试限定在指定路径或主机，避免范围扩大。"
            ),
        )
        discovery_group = self._group(parent, "参数发现")
        self._check(discovery_group, 0, "只做参数发现", "only_discovery")
        self._check(discovery_group, 1, "跳过全部发现", "skip_discovery")
        self._check(
            discovery_group, 2, "跳过 Header 反射检查", "skip_reflection_header"
        )
        self._check(
            discovery_group, 3, "跳过 Cookie 反射检查", "skip_reflection_cookie"
        )
        self._check(
            discovery_group, 4, "跳过 Path 反射检查", "skip_reflection_path"
        )

        mining_group = self._group(parent, "参数挖掘")
        self._path(
            mining_group, 0, "本地参数字典", "mining_dict_word", save=False
        )
        self._combo(
            mining_group,
            1,
            "远程字典",
            "remote_wordlists",
            ("", "burp", "assetnote", "burp,assetnote"),
            "",
        )
        self._check(mining_group, 2, "跳过全部挖掘", "skip_mining")
        self._check(
            mining_group, 3, "跳过字典挖掘", "skip_mining_dict"
        )
        self._check(
            mining_group, 4, "跳过 DOM 参数名挖掘", "skip_mining_dom"
        )

        scope_group = self._group(parent, "范围过滤")
        self._text(
            scope_group,
            0,
            "仅包含 URL（每行一个正则）",
            "include_urls",
            3,
        )
        self._text(
            scope_group,
            1,
            "排除 URL（每行一个正则）",
            "exclude_urls",
            3,
        )
        self._text(
            scope_group,
            2,
            "Out-of-Scope 域名（每行一个，支持通配符）",
            "out_of_scope",
            3,
        )
        self._path(
            scope_group, 3, "Out-of-Scope 文件", "out_of_scope_file"
        )

    def _build_scan_xss(self, parent: ttk.Frame) -> None:
        self._help_panel(
            parent,
            "XSS 引擎怎么选",
            (
                "默认编码器适合普通测试；自定义 Payload 文件适合已有测试集合。"
                "存储型 XSS 会检查后续页面，盲 XSS 需要回调服务。深度扫描更完整，"
                "但请求量和运行时间会明显增加，新手先用标准扫描。"
            ),
        )
        encoder_group = self._group(parent, "Payload 编码器")
        encoder_values = (
            "none",
            "url",
            "2url",
            "3url",
            "4url",
            "html",
            "htmlpad",
            "base64",
            "unicode",
            "zwsp",
        )
        for index, value in enumerate(encoder_values):
            var = tk.BooleanVar(value=value in {"url", "html"})
            self.encoder_vars[value] = var
            ttk.Checkbutton(
                encoder_group,
                text=value,
                variable=var,
            ).grid(row=index // 5, column=index % 5, sticky="w", padx=5, pady=3)

        payload_group = self._group(parent, "Payload 与回调")
        self._combo(
            payload_group,
            0,
            "远程 Payload",
            "remote_payloads",
            ("", "portswigger", "payloadbox", "portswigger,payloadbox"),
            "",
        )
        self._path(payload_group, 1, "自定义 Payload 文件", "custom_payload")
        self._check(
            payload_group, 2, "只使用自定义 Payload", "only_custom_payload"
        )
        self._path(
            payload_group,
            3,
            "自定义盲 XSS Payload 文件",
            "custom_blind_payload",
        )
        self._entry(
            payload_group, 4, "盲 XSS 回调 URL", "blind_callback"
        )
        self._check(
            payload_group,
            5,
            "启用 interactsh 盲 OOB",
            "blind_oob",
        )
        self._entry(
            payload_group,
            6,
            "interactsh 服务器（可选）",
            "blind_oob_servers",
        )
        self._password(
            payload_group,
            7,
            "interactsh 认证 Secret",
            "blind_oob_secret",
        )
        self._entry(
            payload_group, 8, "OOB 等待秒数", "blind_oob_wait", "30"
        )
        self._entry(
            payload_group, 9, "自定义 alert 值", "custom_alert_value", "1"
        )
        self._combo(
            payload_group,
            10,
            "自定义 alert 类型",
            "custom_alert_type",
            ("none", "str"),
            "none",
        )
        self._entry(
            payload_group, 11, "注入标记", "inject_marker", "FUZZ"
        )

        engine_group = self._group(parent, "扫描引擎")
        self._entry(
            engine_group,
            0,
            "每参数最大基础 Payload（0=内置上限）",
            "max_payloads_per_param",
            "0",
        )
        self._check(
            engine_group, 1, "深度扫描：找到后继续测试全部 Payload", "deep_scan"
        )
        self._check(
            engine_group, 2, "分析同源外部 JavaScript", "analyze_external_js"
        )
        self._check(engine_group, 3, "跳过 AST DOM XSS 分析", "skip_ast_analysis")
        self._check(engine_group, 4, "启用 HPP 参数污染测试", "hpp")
        self._check(
            engine_group, 5, "检测过期 JavaScript 库", "detect_outdated_libs"
        )
        self._check(engine_group, 6, "完全跳过 XSS 注入", "skip_xss_scanning")

        sxss_group = self._group(parent, "存储型 XSS")
        self._check(sxss_group, 0, "启用存储型 XSS 模式", "sxss")
        self._entry(sxss_group, 1, "存储型 XSS 检查 URL", "sxss_url")
        self._combo(
            sxss_group,
            2,
            "检查方法",
            "sxss_method",
            ("GET", "POST"),
            "GET",
        )
        self._entry(sxss_group, 3, "检查重试次数", "sxss_retries", "3")

    def _build_scan_waf(self, parent: ttk.Frame) -> None:
        self._help_panel(
            parent,
            "WAF 与高级选项",
            (
                "普通本地靶场通常把 WAF 策略设为 off。只有靶场明确启用 WAF 时，"
                "才考虑 auto 或 force；这些选项会增加请求和测试时间。"
                "目标仍受本地/内网范围保护，不会因此放行公网地址。"
            ),
        )

        waf_group = self._group(parent, "WAF")
        self._combo(
            waf_group,
            0,
            "WAF 策略",
            "waf_bypass",
            ("auto", "off", "force"),
            "off",
        )
        self._entry(
            waf_group, 1, "强制 WAF 类型（force 时使用）", "force_waf"
        )
        self._check(waf_group, 2, "跳过 WAF 指纹探测", "skip_waf_probe")
        self._check(waf_group, 3, "启用自适应 WAF 规避", "waf_evasion")
        self._entry(
            waf_group, 4, "WAF 最低置信度（0.0-1.0）", "waf_min_confidence", "0.3"
        )

        misc_group = self._group(parent, "其他高级")
        self._check(misc_group, 0, "包含 HTTP 请求", "include_request")
        self._check(misc_group, 1, "包含 HTTP 响应", "include_response")
        self._check(misc_group, 2, "包含请求和响应", "include_all")
        self._check(misc_group, 3, "静默全部普通日志", "silence")

    def _build_scan_output(self, parent: ttk.Frame) -> None:
        self._help_panel(
            parent,
            "报告怎么选",
            (
                "plain 适合直接阅读；json/jsonl 适合程序处理；markdown 适合整理"
                "测试记录；SARIF 适合 CI/安全平台；TOML 适合配置或结构化存档。"
                "填写报告保存路径后，Dalfox 会把结果写入该文件。"
            ),
        )
        report_group = self._group(parent, "报告")
        self._combo(
            report_group,
            0,
            "输出格式",
            "format",
            ("plain", "json", "jsonl", "markdown", "sarif", "toml"),
            "plain",
        )
        self._path(report_group, 1, "报告保存路径", "output", save=True)
        self._combo(
            report_group,
            2,
            "POC 格式",
            "poc_type",
            ("plain", "curl", "httpie", "http-request"),
            "plain",
        )
        self._entry(report_group, 3, "最多结果数", "limit")
        self._combo(
            report_group,
            4,
            "计入限制的结果类型",
            "limit_result_type",
            ("all", "v", "r", "a", "i"),
            "all",
        )
        self._entry(
            report_group, 5, "仅显示结果类型（如 v,r,a）", "only_poc"
        )
        self._path(report_group, 6, "基线 JSON/JSONL 报告", "baseline")
        self._combo(
            report_group,
            7,
            "基线处理",
            "baseline_mode",
            ("filter", "annotate"),
            "filter",
        )

        tips = ttk.Label(
            parent,
            text=(
                "建议：普通查看选 plain；给程序处理选 json/jsonl；"
                "需要漏洞报告选 markdown 或 sarif。"
            ),
            style="Muted.TLabel",
            wraplength=1050,
        )
        tips.pack(fill="x", padx=10, pady=10)

    def _build_payload_tab(self) -> None:
        scroll = ScrollableFrame(self.payload_tab)
        scroll.pack(fill="both", expand=True)
        wrapper = ttk.Frame(scroll.inner, padding=18)
        wrapper.pack(fill="both", expand=True)
        ttk.Label(
            wrapper,
            text="Payload 查询与生成",
            font=("Microsoft YaHei UI", 16, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            wrapper,
            text=(
                "这里不会扫描网站。它只把 Dalfox 内置或远程 Payload 资源列出来，"
                "方便你查看、复制、保存或用于扫描页。"
            ),
            style="Muted.TLabel",
            wraplength=1080,
        ).pack(anchor="w", pady=(4, 12))

        steps = ttk.LabelFrame(wrapper, text="三步使用", padding=10)
        steps.pack(fill="x", pady=(0, 10))
        ttk.Label(
            steps,
            text=(
                "1. 点击下面的常用按钮，或在“完整分类”中选择一个项目。\n"
                "2. 查看分类说明，确认用途以及是否会联网。\n"
                "3. 点击“开始查询”，结果会出现在窗口下方的“实时输出”。"
            ),
            justify="left",
        ).pack(anchor="w")

        quick_group = self._group(wrapper, "常用 Payload（点击后立即查询）")
        quick_actions = (
            ("常用 JS 执行", "javascript"),
            ("事件处理器", "event-handlers"),
            ("HTML 标签", "useful-tags"),
            ("特殊字符", "special-chars"),
            ("全部本地资源", "all"),
            ("PortSwigger 在线库", "portswigger"),
            ("PayloadBox 在线库", "payloadbox"),
            ("盲 XSS 模板", "blind"),
        )
        for index, (button_text, selector) in enumerate(quick_actions):
            ttk.Button(
                quick_group,
                text=button_text,
                command=lambda key=selector: self._quick_payload(key),
            ).grid(
                row=index // 4,
                column=index % 4,
                sticky="ew",
                padx=4,
                pady=4,
            )
        for column in range(4):
            quick_group.columnconfigure(column, weight=1)

        group = self._group(wrapper, "完整分类与输出设置")
        selector_widget = self._combo(
            group,
            0,
            "Payload 分类",
            "payload_selector",
            tuple(item["label"] for item in PAYLOAD_SELECTORS.values()),
            PAYLOAD_SELECTORS["javascript"]["label"],
        )
        selector_widget.bind(
            "<<ComboboxSelected>>", lambda _event: self._update_payload_description()
        )
        self._check(
            group,
            1,
            "JSON 格式输出（适合复制到其他程序）",
            "payload_json",
        )
        self._path(group, 2, "配置文件", "payload_config")

        description_group = ttk.LabelFrame(wrapper, text="当前分类说明", padding=10)
        description_group.pack(fill="x", pady=(10, 0))
        self.payload_description_var = tk.StringVar()
        ttk.Label(
            description_group,
            textvariable=self.payload_description_var,
            justify="left",
            wraplength=1070,
        ).pack(anchor="w")

        actions = ttk.Frame(wrapper)
        actions.pack(fill="x", pady=14)
        ttk.Button(
            actions,
            text="开始查询",
            style="Accent.TButton",
            command=self._start_payload,
        ).pack(side="left")
        ttk.Button(
            actions, text="停止", style="Danger.TButton", command=self._stop_process
        ).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="复制全部输出", command=self._copy_log).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(
            actions, text="保存查询结果", command=self._save_log
        ).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="清空输出", command=self._clear_log).pack(
            side="left", padx=(8, 0)
        )
        ttk.Label(
            actions,
            text="查询结果在下方实时输出中",
            style="Muted.TLabel",
        ).pack(side="right")

        ttk.Label(
            wrapper,
            text=(
                "注意：Payload 查询本身不会访问目标网站；"
                "payloadbox 和 portswigger 分类只连接远程 Payload 库。"
            ),
            style="Warning.TLabel",
            wraplength=1080,
        ).pack(fill="x", anchor="w", padx=8, pady=(0, 12))

    def _build_server_tab(self) -> None:
        scroll = ScrollableFrame(self.server_tab)
        scroll.pack(fill="both", expand=True)
        parent = scroll.inner
        ttk.Label(
            parent,
            text="本地 REST API 服务",
            font=("Microsoft YaHei UI", 16, "bold"),
        ).pack(anchor="w", padx=12, pady=(12, 4))
        ttk.Label(
            parent,
            text=(
                "Dalfox 原生 API 接受的目标不受本 GUI 的本地范围检查控制，"
                "因此这里只保留参数说明与命令预览，不提供一键启动。"
            ),
            style="Warning.TLabel",
            wraplength=1050,
        ).pack(anchor="w", padx=12, pady=(0, 10))
        self._help_panel(
            parent,
            "这一页是做什么的",
            (
                "REST API 适合让其他程序调用 Dalfox，不是普通扫描入口。"
                "绑定地址、端口、并发、CORS 和 API Key 只影响本地服务。"
                "由于服务端还能接受其他目标，本 GUI 不提供启动按钮。"
            ),
        )

        server_group = self._group(parent, "服务参数")
        self._combo(
            server_group,
            0,
            "绑定地址",
            "server_host",
            ("127.0.0.1", "localhost"),
            "127.0.0.1",
        )
        self._entry(server_group, 1, "端口", "server_port", "6664")
        self._password(server_group, 2, "API Key（可选）", "server_api_key")
        self._path(server_group, 3, "服务日志文件", "server_log", save=True)
        self._entry(
            server_group, 4, "服务级全局限速（请求/秒）", "server_rate_limit"
        )
        self._entry(
            server_group, 5, "服务级扫描超时（秒）", "server_scan_timeout"
        )
        self._entry(
            server_group,
            6,
            "最大并发扫描数",
            "server_max_concurrent",
            "100",
        )
        self._entry(server_group, 7, "允许 Host", "server_allowed_hosts")
        self._entry(
            server_group, 8, "保留已完成扫描数", "server_retained", "1000"
        )
        self._entry(
            server_group, 9, "最大请求体字节数", "server_body_bytes", "1048576"
        )

        cors_group = self._group(parent, "CORS 与 JSONP")
        self._entry(
            cors_group, 0, "允许来源", "server_allowed_origins"
        )
        self._entry(
            cors_group,
            1,
            "允许方法",
            "server_cors_methods",
            "GET,POST,OPTIONS,PUT,PATCH,DELETE",
        )
        self._entry(
            cors_group,
            2,
            "允许 Header",
            "server_cors_headers",
            "Content-Type,X-API-KEY,Authorization",
        )
        self._check(cors_group, 3, "启用 JSONP", "server_jsonp")
        self._entry(
            cors_group, 4, "JSONP 回调参数名", "server_callback_name", "callback"
        )

        actions = ttk.Frame(parent)
        actions.pack(fill="x", padx=12, pady=12)
        ttk.Label(
            actions,
            text="接口模式已在 GUI 中禁用，避免绕过目标范围保护。",
            style="Warning.TLabel",
        ).pack(side="left")

    def _build_mcp_tab(self) -> None:
        wrapper = ttk.Frame(self.mcp_tab, padding=18)
        wrapper.pack(fill="both", expand=True)
        ttk.Label(
            wrapper,
            text="MCP stdio 接口",
            font=("Microsoft YaHei UI", 16, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            wrapper,
            text=(
                "此模式供 MCP 客户端通过标准输入输出调用 Dalfox。"
                "它会绕过本 GUI 的目标范围检查，因此这里只保留配置与预览。"
            ),
            style="Muted.TLabel",
            wraplength=1000,
        ).pack(anchor="w", pady=(4, 14))
        self._help_panel(
            wrapper,
            "什么时候使用",
            (
                "只有在你已经配置了支持 MCP 的客户端，并希望它调用 Dalfox 时才需要。"
                "普通新手扫描不需要这一页；它没有网页界面，单独启动后只能等待客户端。"
            ),
        )
        group = self._group(wrapper, "MCP 选项")
        self._path(group, 0, "配置文件", "mcp_config")
        self._check(group, 1, "调试日志", "mcp_debug")
        self._check(group, 2, "关闭颜色", "mcp_no_color", True)
        actions = ttk.Frame(wrapper)
        actions.pack(fill="x", pady=12)
        ttk.Label(
            actions,
            text="MCP 模式已在 GUI 中禁用，避免绕过目标范围保护。",
            style="Warning.TLabel",
        ).pack(side="left")

    def _build_presets_tab(self) -> None:
        wrapper = ttk.Frame(self.presets_tab, padding=18)
        wrapper.pack(fill="both", expand=True)
        ttk.Label(
            wrapper,
            text="新手一键预设",
            font=("Microsoft YaHei UI", 16, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            wrapper,
            text="点击后会切换到扫描页并填好常用参数；不会自动开始扫描。",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(4, 14))
        self._help_panel(
            wrapper,
            "怎么选预设",
            (
                "第一次使用先选“本机安全预检”；确认目标可达和请求量后可选"
                "“标准 XSS 扫描”。深度扫描和存储型 XSS 更慢，建议有基础后再用。"
                "预设只会切换参数，仍需回到扫描页填写目标并勾选授权。"
            ),
        )

        cards = (
            (
                "本机安全预检",
                "只分析目标和参数，不发送攻击 Payload。",
                "dry_run",
            ),
            (
                "标准 XSS 扫描",
                "低并发、限速、标准 Payload，适合开始练习。",
                "standard",
            ),
            (
                "深度 XSS 扫描",
                "启用 deep-scan 与外部 JS 分析，运行时间更长。",
                "deep",
            ),
            (
                "仅发现参数",
                "只做参数发现与挖掘，完全不进行 XSS 注入。",
                "discovery",
            ),
            (
                "存储型 XSS",
                "启用 sxss，并保留手动检查 URL。",
                "stored",
            ),
        )
        for title, description, preset in cards:
            card = ttk.LabelFrame(wrapper, text=title, padding=10)
            card.pack(fill="x", pady=5)
            ttk.Label(card, text=description, style="Muted.TLabel").pack(
                side="left", fill="x", expand=True
            )
            ttk.Button(
                card,
                text="使用此预设",
                command=lambda value=preset: self._use_preset_from_library(value),
            ).pack(side="right")

        tools = self._group(wrapper, "工具")
        self._combo(
            tools,
            0,
            "生成 Shell 补全",
            "completion_shell",
            ("powershell", "bash", "zsh", "fish", "elvish"),
            "powershell",
        )
        ttk.Button(
            tools,
            text="生成补全文件",
            command=self._generate_completion,
        ).grid(row=1, column=0, sticky="w", padx=8, pady=8)

    def _build_about_tab(self) -> None:
        wrapper = ttk.Frame(self.about_tab, padding=20)
        wrapper.pack(fill="both", expand=True)
        ttk.Label(
            wrapper,
            text="关于与安全边界",
            font=("Microsoft YaHei UI", 16, "bold"),
        ).pack(anchor="w")
        text = tk.Text(
            wrapper,
            wrap="word",
            height=20,
            bg="#0b1727",
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
            padx=14,
            pady=14,
        )
        text.pack(fill="both", expand=True, pady=(12, 0))
        text.insert(
            "1.0",
            (
                "应用：Dalfox GUI 1.0\n"
                "Dalfox：v3.2.4，Windows x86_64\n"
                f"可执行文件：{DALFOX}\n"
                f"日志目录：{OUTPUT_DIR}\n\n"
                "安全边界：\n"
                "1. 仅扫描你拥有或已获得明确授权的系统。\n"
                "2. GUI 只接受回环地址、RFC1918/链路本地地址，以及 "
                ".local/.lan/.lab/.test/.internal/.home.arpa 域名。\n"
                "3. API 服务只能绑定 127.0.0.1 或 localhost。\n"
                "4. Cookie、Authorization Header、API Key 和 OOB Secret "
                "不会写入配置；命令预览会脱敏。\n"
                "5. 不自动保存包含敏感请求内容的日志；需要时请手动保存并妥善保管。\n\n"
                "新手建议顺序：\n"
                "选择本机预检 → 检查命令预览 → 开始 Dry Run → 确认范围与请求量 "
                "→ 使用标准扫描 → 查看 POC 与报告。"
            )
        )
        text.configure(state="disabled")

    def _build_console(self, parent: ttk.Frame) -> None:
        preview_box = ttk.LabelFrame(parent, text="命令预览（敏感值已脱敏）", padding=8)
        preview_box.pack(fill="x")
        self.preview_widget = tk.Text(
            preview_box,
            height=3,
            wrap="word",
            bg="#071321",
            fg=COLORS["accent"],
            insertbackground=COLORS["text"],
            relief="flat",
            padx=8,
            pady=6,
        )
        self.preview_widget.pack(fill="x")
        self.preview_widget.configure(state="disabled")

        console_box = ttk.LabelFrame(parent, text="实时输出", padding=8)
        console_box.pack(fill="both", expand=True, pady=(8, 0))
        toolbar = ttk.Frame(console_box)
        toolbar.pack(fill="x", pady=(0, 6))
        ttk.Button(toolbar, text="清空", command=self._clear_log).pack(side="left")
        ttk.Button(toolbar, text="保存日志", command=self._save_log).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(
            toolbar, text="打开日志目录", command=self._open_output_dir
        ).pack(side="left", padx=(6, 0))
        self.run_status = ttk.Label(toolbar, text="就绪", style="Success.TLabel")
        self.run_status.pack(side="right")
        self.progress = ttk.Progressbar(
            toolbar, mode="indeterminate", length=140
        )
        self.progress.pack(side="right", padx=(0, 12))

        log_frame = ttk.Frame(console_box)
        log_frame.pack(fill="both", expand=True)
        self.log_widget = tk.Text(
            log_frame,
            wrap="word",
            bg="#050d18",
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
            padx=10,
            pady=8,
        )
        log_scroll = ttk.Scrollbar(
            log_frame, orient="vertical", command=self.log_widget.yview
        )
        self.log_widget.configure(yscrollcommand=log_scroll.set)
        self.log_widget.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        self.log_widget.tag_configure("error", foreground="#fca5a5")
        self.log_widget.tag_configure("warning", foreground=COLORS["warning"])
        self.log_widget.tag_configure("success", foreground=COLORS["success"])
        self.log_widget.tag_configure("muted", foreground=COLORS["muted"])

    def _build_footer(self) -> None:
        footer = tk.Frame(self, bg=COLORS["bg"], padx=18, pady=6)
        footer.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="范围保护已启用：仅本地/内网实验目标")
        tk.Label(
            footer,
            textvariable=self.status_var,
            bg=COLORS["bg"],
            fg=COLORS["muted"],
            anchor="w",
        ).pack(fill="x")

    def sv(self, name: str, default: str = "") -> tk.StringVar:
        if name not in self.vars:
            self.vars[name] = tk.StringVar(value=default)
        return self.vars[name]

    def bv(self, name: str, default: bool = False) -> tk.BooleanVar:
        if name not in self.bool_vars:
            self.bool_vars[name] = tk.BooleanVar(value=default)
        return self.bool_vars[name]

    def _group(self, parent: tk.Widget, title: str) -> ttk.LabelFrame:
        group = ttk.LabelFrame(parent, text=title, padding=10)
        group.pack(fill="x", padx=10, pady=(8, 0))
        group.columnconfigure(1, weight=1)
        return group

    def _help_panel(self, parent: tk.Widget, title: str, body: str) -> ttk.LabelFrame:
        self.help_panel_count += 1
        panel = ttk.LabelFrame(parent, text=title, padding=10)
        panel.pack(fill="x", padx=10, pady=(10, 0))
        ttk.Label(
            panel,
            text=body,
            justify="left",
            wraplength=1060,
        ).pack(fill="x", anchor="w")
        return panel

    def _entry(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        name: str,
        default: str = "",
    ) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="w", padx=(0, 10), pady=4
        )
        widget = ttk.Entry(parent, textvariable=self.sv(name, default))
        widget.grid(row=row, column=1, sticky="ew", pady=4)
        return widget

    def _password(
        self, parent: ttk.Frame, row: int, label: str, name: str
    ) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="w", padx=(0, 10), pady=4
        )
        widget = ttk.Entry(
            parent, textvariable=self.sv(name), show="*"
        )
        widget.grid(row=row, column=1, sticky="ew", pady=4)
        return widget

    def _combo(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        name: str,
        values: tuple[str, ...],
        default: str,
    ) -> ttk.Combobox:
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="w", padx=(0, 10), pady=4
        )
        widget = ttk.Combobox(
            parent,
            textvariable=self.sv(name, default),
            values=values,
            state="readonly",
        )
        widget.grid(row=row, column=1, sticky="ew", pady=4)
        return widget

    def _check(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        name: str,
        default: bool = False,
    ) -> ttk.Checkbutton:
        widget = ttk.Checkbutton(
            parent, text=label, variable=self.bv(name, default)
        )
        widget.grid(row=row, column=0, columnspan=2, sticky="w", pady=3)
        return widget

    def _text(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        name: str,
        height: int,
    ) -> tk.Text:
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="nw", padx=(0, 10), pady=4
        )
        widget = tk.Text(
            parent,
            height=height,
            wrap="none",
            bg="#0c1828",
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="solid",
            borderwidth=1,
        )
        widget.grid(row=row, column=1, sticky="ew", pady=4)
        widget.bind("<<Modified>>", lambda _event: self._text_modified(widget))
        self.text_widgets[name] = widget
        return widget

    def _path(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        name: str,
        save: bool = False,
    ) -> None:
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="w", padx=(0, 10), pady=4
        )
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=1, sticky="ew", pady=4)
        frame.columnconfigure(0, weight=1)
        ttk.Entry(frame, textvariable=self.sv(name)).grid(
            row=0, column=0, sticky="ew"
        )
        ttk.Button(
            frame,
            text="浏览",
            command=lambda: self._choose_path(name, save=save),
        ).grid(row=0, column=1, padx=(6, 0))

    def _text_modified(self, widget: tk.Text) -> None:
        if widget.edit_modified():
            widget.edit_modified(False)
            self._schedule_preview()

    def _choose_path(self, name: str, save: bool) -> None:
        if save:
            filename = filedialog.asksaveasfilename(
                initialdir=str(OUTPUT_DIR),
                defaultextension=".txt",
                filetypes=(("All files", "*.*"),),
            )
        else:
            filename = filedialog.askopenfilename(
                initialdir=str(OUTPUT_DIR),
                filetypes=(("All files", "*.*"),),
            )
        if filename:
            self.sv(name).set(filename)

    def _choose_target_file(self) -> None:
        filename = filedialog.askopenfilename(
            initialdir=str(OUTPUT_DIR),
            filetypes=(
                ("Target files", "*.txt *.har"),
                ("Text files", "*.txt"),
                ("HAR files", "*.har"),
                ("All files", "*.*"),
            ),
        )
        if filename:
            self.sv("target").set(filename)
            suffix = Path(filename).suffix.lower()
            self.sv("input_type").set("har" if suffix == ".har" else "file")

    def _bind_preview_updates(self) -> None:
        for variable in [*self.vars.values(), *self.bool_vars.values()]:
            variable.trace_add("write", lambda *_args: self._schedule_preview())
        for variable in self.encoder_vars.values():
            variable.trace_add("write", lambda *_args: self._schedule_preview())

    def _schedule_preview(self) -> None:
        if self.preview_after_id:
            self.after_cancel(self.preview_after_id)
        self.preview_after_id = self.after(150, self._refresh_preview)

    def _current_tab_name(self) -> str:
        selected = self.notebook.select()
        if not selected:
            return ""
        return self.notebook.tab(selected, "text")

    def _text_value(self, name: str) -> str:
        widget = self.text_widgets.get(name)
        if widget is None:
            return ""
        return widget.get("1.0", "end-1c")

    def _add_value(self, args: list[str], flag: str, name: str) -> None:
        value = self.sv(name).get().strip()
        if value:
            args.extend((flag, value))

    def _add_text_lines(self, args: list[str], flag: str, name: str) -> None:
        for value in split_multiline(self._text_value(name)):
            args.extend((flag, value))

    def build_scan_args(self) -> list[str]:
        args = [str(DALFOX), "scan"]
        if self.bv("no_color", True).get():
            args.append("--no-color")
        self._add_value(args, "--config", "config")
        self._add_value(args, "--input-type", "input_type")
        self._add_value(args, "--dedup-urls", "dedup_urls")
        self._add_value(args, "--state-file", "state_file")

        if self.bv("debug").get():
            args.append("--debug")
        if self.bv("silence").get():
            args.append("--silence")
        if self.bv("dry_run").get():
            args.append("--dry-run")
        if self.bv("stream_findings").get():
            args.append("--stream-findings")

        output = self.sv("output").get().strip()
        if output:
            self._add_value(args, "--format", "format")
            args.extend(("--output", output))
        self._add_value(args, "--poc-type", "poc_type")
        self._add_value(args, "--limit", "limit")
        self._add_value(args, "--limit-result-type", "limit_result_type")
        self._add_value(args, "--only-poc", "only_poc")
        self._add_value(args, "--baseline", "baseline")
        self._add_value(args, "--baseline-mode", "baseline_mode")
        if self.bv("include_request").get():
            args.append("--include-request")
        if self.bv("include_response").get():
            args.append("--include-response")
        if self.bv("include_all").get():
            args.append("--include-all")

        self._add_value(args, "--method", "method")
        self._add_value(args, "--data", "data")
        self._add_text_lines(args, "--headers", "headers")
        self._add_text_lines(args, "--cookies", "cookies")
        self._add_value(args, "--user-agent", "user_agent")
        self._add_value(args, "--cookie-from-raw", "cookie_from_raw")
        for value in split_multiline(self.sv("param").get().replace(",", "\n")):
            args.extend(("--param", value))

        session_check = self.sv("session_check").get().strip()
        if session_check:
            args.extend(("--session-check", session_check))
        self._add_value(args, "--session-check-url", "session_check_url")
        self._add_value(args, "--on-session-loss", "on_session_loss")

        for value in split_multiline(
            self.sv("include_urls").get()
        ):
            args.extend(("--include-url", value))
        for value in split_multiline(self.sv("exclude_urls").get()):
            args.extend(("--exclude-url", value))
        for value in split_multiline(self.sv("ignore_param").get().replace(",", "\n")):
            args.extend(("--ignore-param", value))
        for value in split_multiline(self.sv("out_of_scope").get()):
            args.extend(("--out-of-scope", value))
        self._add_value(args, "--out-of-scope-file", "out_of_scope_file")

        if self.bv("only_discovery").get():
            args.append("--only-discovery")
        if self.bv("skip_discovery").get():
            args.append("--skip-discovery")
        if self.bv("skip_reflection_header").get():
            args.append("--skip-reflection-header")
        if self.bv("skip_reflection_cookie").get():
            args.append("--skip-reflection-cookie")
        if self.bv("skip_reflection_path").get():
            args.append("--skip-reflection-path")

        self._add_value(args, "--mining-dict-word", "mining_dict_word")
        self._add_value(args, "--remote-wordlists", "remote_wordlists")
        if self.bv("skip_mining").get():
            args.append("--skip-mining")
        if self.bv("skip_mining_dict").get():
            args.append("--skip-mining-dict")
        if self.bv("skip_mining_dom").get():
            args.append("--skip-mining-dom")

        self._add_value(args, "--timeout", "timeout")
        self._add_value(args, "--scan-timeout", "scan_timeout")
        self._add_value(args, "--delay", "delay")
        self._add_value(args, "--rate-limit", "rate_limit")
        self._add_value(args, "--retries", "retries")
        self._add_value(args, "--retry-delay", "retry_delay")
        self._add_value(args, "--proxy", "proxy")
        if self.sv("insecure").get() == "开启 --insecure":
            args.append("--insecure")
        elif self.sv("insecure").get() == "关闭 --insecure=false":
            args.append("--insecure=false")
        if self.bv("follow_redirects").get():
            args.append("--follow-redirects")
        self._add_value(args, "--ignore-return", "ignore_return")

        self._add_value(args, "--workers", "workers")
        self._add_value(args, "--max-concurrent-targets", "max_concurrent_targets")
        self._add_value(args, "--max-targets-per-host", "max_targets_per_host")

        encoders = [name for name, var in self.encoder_vars.items() if var.get()]
        if encoders:
            args.extend(("--encoders", ",".join(encoders)))
        self._add_value(args, "--remote-payloads", "remote_payloads")
        self._add_value(args, "--custom-payload", "custom_payload")
        if self.bv("only_custom_payload").get():
            args.append("--only-custom-payload")
        self._add_value(
            args, "--custom-blind-xss-payload", "custom_blind_payload"
        )
        self._add_value(args, "--blind", "blind_callback")
        if self.bv("blind_oob").get():
            servers = self.sv("blind_oob_servers").get().strip()
            args.append(f"--blind-oob={servers}" if servers else "--blind-oob")
        self._add_value(args, "--blind-oob-secret", "blind_oob_secret")
        self._add_value(args, "--blind-oob-wait", "blind_oob_wait")
        self._add_value(args, "--custom-alert-value", "custom_alert_value")
        self._add_value(args, "--custom-alert-type", "custom_alert_type")
        self._add_value(args, "--inject-marker", "inject_marker")
        self._add_value(
            args, "--max-payloads-per-param", "max_payloads_per_param"
        )
        if self.bv("deep_scan").get():
            args.append("--deep-scan")
        if self.bv("sxss").get():
            args.append("--sxss")
        self._add_value(args, "--sxss-url", "sxss_url")
        self._add_value(args, "--sxss-method", "sxss_method")
        self._add_value(args, "--sxss-retries", "sxss_retries")
        if self.bv("skip_ast_analysis").get():
            args.append("--skip-ast-analysis")
        if self.bv("analyze_external_js").get():
            args.append("--analyze-external-js")
        if self.bv("hpp").get():
            args.append("--hpp")
        if self.bv("detect_outdated_libs").get():
            args.append("--detect-outdated-libs")
        if self.bv("skip_xss_scanning").get():
            args.append("--skip-xss-scanning")

        self._add_value(args, "--waf-bypass", "waf_bypass")
        if self.bv("skip_waf_probe").get():
            args.append("--skip-waf-probe")
        self._add_value(args, "--force-waf", "force_waf")
        if self.bv("waf_evasion").get():
            args.append("--waf-evasion")
        self._add_value(args, "--waf-min-confidence", "waf_min_confidence")

        target = self.sv("target").get().strip()
        if target:
            args.append(target)
        return args

    def build_payload_args(self) -> list[str]:
        args = [str(DALFOX), "payload"]
        display_selector = self.sv(
            "payload_selector", PAYLOAD_SELECTORS["javascript"]["label"]
        ).get().strip()
        selector = PAYLOAD_LABEL_TO_KEY.get(display_selector, display_selector)
        if selector:
            args.append(selector)
        args.append("--no-color")
        self._add_value(args, "--config", "payload_config")
        if self.bv("payload_json").get():
            args.append("--json")
        return args

    def build_server_args(self) -> list[str]:
        args = [str(DALFOX), "server", "--no-color"]
        self._add_value(args, "--host", "server_host")
        self._add_value(args, "--port", "server_port")
        self._add_value(args, "--api-key", "server_api_key")
        self._add_value(args, "--log-file", "server_log")
        self._add_value(args, "--rate-limit", "server_rate_limit")
        self._add_value(args, "--scan-timeout", "server_scan_timeout")
        self._add_value(
            args, "--max-concurrent-scans", "server_max_concurrent"
        )
        self._add_value(args, "--allowed-hosts", "server_allowed_hosts")
        self._add_value(args, "--max-retained-scans", "server_retained")
        self._add_value(args, "--max-body-bytes", "server_body_bytes")
        self._add_value(args, "--allowed-origins", "server_allowed_origins")
        self._add_value(args, "--cors-allow-methods", "server_cors_methods")
        self._add_value(args, "--cors-allow-headers", "server_cors_headers")
        if self.bv("server_jsonp").get():
            args.append("--jsonp")
        self._add_value(args, "--callback-param-name", "server_callback_name")
        return args

    def build_mcp_args(self) -> list[str]:
        args = [str(DALFOX), "mcp", "--no-color"]
        self._add_value(args, "--config", "mcp_config")
        if self.bv("mcp_debug").get():
            args.append("--debug")
        return args

    def _current_preview_args(self) -> list[str]:
        tab = self._current_tab_name()
        if tab == "扫描":
            return self.build_scan_args()
        if tab == "Payload 查询":
            return self.build_payload_args()
        if tab == "本地 API 服务":
            return self.build_server_args()
        if tab == "MCP 接口":
            return self.build_mcp_args()
        return []

    def _refresh_preview(self) -> None:
        self.preview_after_id = None
        try:
            args = self._current_preview_args()
            text = preview_command(args) if args else "当前页面没有可执行命令。"
        except Exception as exc:
            text = f"命令预览失败：{exc}"
        self.preview_widget.configure(state="normal")
        self.preview_widget.delete("1.0", "end")
        self.preview_widget.insert("1.0", text)
        self.preview_widget.configure(state="disabled")

    def _validate_scan_scope(self) -> list[str]:
        targets = validate_target_input(
            self.sv("target").get(), self.sv("input_type", "auto").get()
        )
        validate_optional_url(
            self.sv("session_check_url").get(), "会话检测 URL"
        )
        validate_optional_url(self.sv("sxss_url").get(), "存储型 XSS 检查 URL")
        return targets

    def _start_dry_run(self) -> None:
        self.bv("dry_run").set(True)
        self._start_scan()

    def _start_scan(self) -> None:
        if not self._authorized():
            return
        if not self.sv("target").get().strip():
            messagebox.showwarning("缺少目标", "请先输入目标 URL 或选择目标文件。")
            return
        try:
            self._validate_scan_scope()
        except ScopeError as exc:
            messagebox.showerror("目标范围校验失败", str(exc))
            return
        self._start_process(self.build_scan_args(), "XSS 扫描")

    def _start_payload(self) -> None:
        self._start_process(self.build_payload_args(), "Payload 查询")

    def _update_payload_description(self) -> None:
        display_selector = self.sv(
            "payload_selector", PAYLOAD_SELECTORS["javascript"]["label"]
        ).get().strip()
        key = PAYLOAD_LABEL_TO_KEY.get(display_selector, display_selector)
        item = PAYLOAD_SELECTORS.get(key)
        if item is None:
            self.payload_description_var.set("请选择一个有效的 Payload 分类。")
            return
        self.payload_description_var.set(
            f"{item['label']}\n内部选择器：{key}\n\n{item['description']}"
        )

    def _quick_payload(self, key: str) -> None:
        item = PAYLOAD_SELECTORS.get(key)
        if item is None:
            return
        self.sv("payload_selector").set(item["label"])
        self._update_payload_description()
        self.notebook.select(self.payload_tab)
        self._start_payload()

    def _copy_log(self) -> None:
        text = self.log_widget.get("1.0", "end-1c")
        if not text:
            messagebox.showinfo("没有内容", "当前输出为空。")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set("输出已复制到剪贴板")
        self._append_log("\n输出已复制到剪贴板。\n", "success")

    def _authorized(self) -> bool:
        if self.auth_var.get():
            return True
        messagebox.showwarning(
            "需要授权确认",
            "开始扫描前必须勾选：已获得目标所有者的明确授权，且目标属于本地/内网实验环境。",
        )
        return False

    def _start_process(self, args: list[str], mode: str) -> None:
        if self.process and self.process.poll() is None:
            messagebox.showwarning("正在运行", "请先停止当前任务。")
            return
        if not DALFOX.is_file():
            messagebox.showerror("Dalfox 不存在", str(DALFOX))
            return

        self._append_log(f"\n$ {preview_command(args)}\n", "muted")
        self.running_mode = mode
        self.run_status.configure(text=f"运行中：{mode}", style="Success.TLabel")
        self.progress.start(12)
        self.status_var.set(f"正在运行：{mode}")

        environment = os.environ.copy()
        environment["NO_COLOR"] = "1"
        try:
            self.process = subprocess.Popen(
                args,
                cwd=str(DALFOX.parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=environment,
                creationflags=CREATE_NO_WINDOW,
            )
        except OSError as exc:
            self._append_log(f"启动失败：{exc}\n", "error")
            self._set_idle("启动失败")
            return

        self.reader_thread = threading.Thread(
            target=self._read_process_output,
            name="dalfox-output-reader",
            daemon=True,
        )
        self.reader_thread.start()

    def _read_process_output(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        try:
            for line in iter(process.stdout.readline, ""):
                self.events.put(("log", line))
        finally:
            exit_code = process.wait()
            self.events.put(("done", exit_code))

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "done":
                    exit_code = int(payload)
                    if exit_code == 0:
                        self._append_log(
                            f"\n[{self.running_mode}] 完成，退出码 0\n", "success"
                        )
                        self._set_idle("完成")
                    else:
                        self._append_log(
                            f"\n[{self.running_mode}] 结束，退出码 {exit_code}\n",
                            "warning" if exit_code > 0 else "muted",
                        )
                        self._set_idle(f"退出码 {exit_code}")
        except queue.Empty:
            pass
        self.after(120, self._drain_events)

    def _append_log(self, text: str, tag: str | None = None) -> None:
        self.log_widget.configure(state="normal")
        if tag is None:
            lowered = text.lower()
            if "error" in lowered or "failed" in lowered:
                tag = "error"
            elif "warn" in lowered:
                tag = "warning"
            elif "xss found" in lowered or "vulnerable" in lowered:
                tag = "success"
        self.log_widget.insert("end", text, tag or "")
        self.log_widget.see("end")
        self.log_widget.configure(state="disabled")

    def _set_idle(self, status: str) -> None:
        self.progress.stop()
        self.run_status.configure(text=status, style="Success.TLabel")
        self.status_var.set(f"{status} | 范围保护已启用")
        self.process = None
        self.reader_thread = None
        self.running_mode = ""

    def _stop_process(self) -> None:
        process = self.process
        if not process or process.poll() is not None:
            self._append_log("当前没有正在运行的任务。\n", "muted")
            return
        self._append_log("正在停止任务……\n", "warning")
        try:
            process.terminate()
        except OSError as exc:
            self._append_log(f"停止失败：{exc}\n", "error")

    def _clear_log(self) -> None:
        self.log_widget.configure(state="normal")
        self.log_widget.delete("1.0", "end")
        self.log_widget.configure(state="disabled")

    def _save_log(self) -> None:
        default_name = datetime.now().strftime("dalfox-gui-%Y%m%d-%H%M%S.txt")
        filename = filedialog.asksaveasfilename(
            initialdir=str(OUTPUT_DIR),
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
        )
        if not filename:
            return
        try:
            Path(filename).write_text(
                self.log_widget.get("1.0", "end-1c"),
                encoding="utf-8",
            )
        except OSError as exc:
            messagebox.showerror("保存失败", str(exc))
            return
        self._append_log(f"日志已保存：{filename}\n", "success")

    def _open_output_dir(self) -> None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        os.startfile(str(OUTPUT_DIR))

    def _reset_scan_modes(self) -> None:
        for name in (
            "dry_run",
            "stream_findings",
            "only_discovery",
            "skip_discovery",
            "deep_scan",
            "sxss",
            "hpp",
            "waf_evasion",
            "skip_xss_scanning",
        ):
            self.bv(name).set(False)

    def _apply_scan_preset(self, preset: str) -> None:
        self._reset_scan_modes()
        if preset == "dry_run":
            self.bv("dry_run").set(True)
            self.sv("workers").set("10")
            self.sv("rate_limit").set("10")
        elif preset == "standard":
            self.sv("workers").set("10")
            self.sv("rate_limit").set("10")
            self.sv("delay").set("50")
            self.sv("timeout").set("10")
            self.sv("scan_timeout").set("300")
            self.sv("waf_bypass").set("off")
        elif preset == "deep":
            self.bv("deep_scan").set(True)
            self.bv("analyze_external_js").set(True)
            self.sv("workers").set("10")
            self.sv("rate_limit").set("10")
            self.sv("scan_timeout").set("600")
            self.sv("max_payloads_per_param").set("0")
        elif preset == "discovery":
            self.bv("only_discovery").set(True)
            self.bv("skip_xss_scanning").set(True)
            self.sv("workers").set("5")
            self.sv("rate_limit").set("5")
        elif preset == "stored":
            self.bv("sxss").set(True)
            self.sv("sxss_method").set("GET")
            self.sv("sxss_retries").set("3")
            self.sv("workers").set("5")
            self.sv("rate_limit").set("5")
        self.status_var.set(f"已应用预设：{preset}")
        self._schedule_preview()

    def _use_preset_from_library(self, preset: str) -> None:
        self._apply_scan_preset(preset)
        self.notebook.select(self.scan_tab)
        self.scan_options_notebook.select(0)
        self.status_var.set("预设已应用；填写目标并确认授权后即可运行")

    def _generate_completion(self) -> None:
        shell = self.sv("completion_shell", "powershell").get()
        target = OUTPUT_DIR / f"dalfox-completion.{shell}"
        if shell in {"powershell", "bash", "zsh", "fish", "elvish"}:
            pass
        if target.exists():
            if not messagebox.askyesno("文件已存在", f"覆盖 {target} 吗？"):
                return
        args = [str(DALFOX), "completion", shell, "--no-color"]
        try:
            result = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=CREATE_NO_WINDOW,
            )
        except OSError as exc:
            messagebox.showerror("生成失败", str(exc))
            return
        if result.returncode != 0:
            messagebox.showerror(
                "生成失败", result.stderr or result.stdout or "Dalfox 返回错误"
            )
            return
        target.write_text(result.stdout, encoding="utf-8")
        self._append_log(f"补全文件已生成：{target}\n", "success")
        messagebox.showinfo("生成完成", str(target))

    def _on_close(self) -> None:
        if self.process and self.process.poll() is None:
            if not messagebox.askyesno("退出", "任务仍在运行，确定退出吗？"):
                return
            try:
                self.process.terminate()
            except OSError:
                pass
        self.destroy()


def selftest() -> int:
    allowed = (
        "http://127.0.0.1:8080/?q=1",
        "http://192.168.1.10/",
        "https://dvwa.local/",
    )
    blocked = (
        "https://example.com/",
        "http://8.8.8.8/",
        "ftp://127.0.0.1/",
    )
    for target in allowed:
        validate_url(target)
    for target in blocked:
        try:
            validate_url(target)
        except ScopeError:
            continue
        raise AssertionError(f"public target was not blocked: {target}")
    redacted = preview_command(
        [
            "dalfox.exe",
            "scan",
            "--cookies",
            "session=secret",
            "--headers",
            "Authorization: Bearer secret",
            "http://127.0.0.1/",
        ]
    )
    assert "secret" not in redacted
    print("selftest-ok")
    return 0


def ui_smoke_test() -> int:
    app = DalfoxGui(start_hidden=True)
    try:
        app.sv("target").set("http://127.0.0.1:8080/?q=FUZZ")
        app.sv("input_type").set("url")
        app.bv("deep_scan").set(True)
        app.bv("sxss").set(True)
        app.bv("blind_oob").set(True)
        app.sv("blind_oob_secret").set("super-secret")
        app.text_widgets["headers"].insert("1.0", "Authorization: Bearer super-secret")
        app.text_widgets["cookies"].insert("1.0", "session=super-secret")
        args = app.build_scan_args()
        assert "scan" in args
        assert "http://127.0.0.1:8080/?q=FUZZ" in args
        assert "--deep-scan" in args
        assert "--sxss" in args
        assert "--blind-oob" in args
        assert "super-secret" not in preview_command(args)
        assert app.payload_description_var.get().startswith("JavaScript")
        assert app.help_panel_count >= 10
        payload_args = app.build_payload_args()
        assert "payload" in payload_args
        assert "javascript" in payload_args
        server_args = app.build_server_args()
        assert "server" in server_args
        assert "127.0.0.1" in server_args
        mcp_args = app.build_mcp_args()
        assert "mcp" in mcp_args
        assert app.notebook.index("end") == 6
        app.update_idletasks()
        print("ui-smoke-test-ok")
        return 0
    finally:
        app.destroy()


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(selftest())
    if "--ui-smoke-test" in sys.argv:
        raise SystemExit(ui_smoke_test())
    DalfoxGui().mainloop()
