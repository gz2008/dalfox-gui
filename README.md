# Dalfox GUI

面向 Windows 的 Dalfox 图形控制台。它把 Dalfox 的 XSS 扫描、
Payload 查询、参数发现和报告功能组织成中文界面，适合本地靶场和
明确授权的安全测试。

![Dalfox GUI icon](dalfox-gui-icon.png)

## 功能

- 标准、深度、Dry Run、参数发现、存储型 XSS 等一键预设。
- 完整的 Dalfox `scan` 参数界面：
  - 单 URL、URL 文件、raw HTTP 和 HAR 输入。
  - HTTP 方法、Headers、Cookies、请求体、代理和会话检测。
  - 参数发现、字典挖掘、URL/域名范围过滤。
  - DOM XSS、存储型 XSS、盲 XSS、自定义 Payload 和编码器。
  - 并发、限速、超时、重试、WAF 与报告格式。
  - JSON、JSONL、Markdown、SARIF 和 TOML 输出。
- 中文 Payload 分类说明与一键查询。
- 实时输出、停止、复制、保存日志和命令预览。
- Cookie、Authorization 和 Secret 在命令预览中自动脱敏。
- 启动前执行目标范围检查。

## 安全边界

本项目只允许扫描：

- `localhost` 和回环地址。
- RFC1918 私网地址和 IPv6 链路本地地址。
- `.local`、`.lan`、`.lab`、`.test`、`.internal`、
  `.home.arpa` 本地实验域名。

公网域名和公网 IP 会在启动 Dalfox 前被拒绝。不要移除这层保护后
扫描未授权系统。

Dalfox 的 REST API 和 MCP 模式可以接受绕开本 GUI 范围检查的目标，
因此界面保留参数说明和命令预览，但不提供一键启动。

## 环境要求

- Windows 10/11。
- Python 3.10 或更高版本，包含 Tk。
- [Dalfox](https://github.com/hahwul/dalfox) v3.2.4。

本项目不分发 Dalfox 二进制。请从
[Dalfox Releases](https://github.com/hahwul/dalfox/releases) 下载并
自行校验官方提供的 SHA256。

## 安装

1. 下载并解压 Dalfox Windows 版本。
2. 克隆本项目：

   ```powershell
   git clone https://github.com/gz2008/dalfox-gui.git
   cd dalfox-gui
   ```

3. 复制配置模板：

   ```powershell
   Copy-Item config.local.example.json config.local.json
   ```

4. 编辑 `config.local.json`，填写 Dalfox 路径和输出目录：

   ```json
   {
     "dalfox_exe": "C:\\tools\\dalfox\\dalfox.exe",
     "output_dir": "C:\\DalfoxGUI\\output"
   }
   ```

也可以使用环境变量：

```powershell
$env:DALFOX_EXE = "C:\tools\dalfox\dalfox.exe"
$env:DALFOX_GUI_OUTPUT = "C:\DalfoxGUI\output"
```

若 Dalfox 已加入 `PATH`，可省略 `dalfox_exe`。

## 启动

```powershell
py -3 dalfox_gui.pyw
```

Windows 调试启动：

```powershell
.\run_debug.cmd
```

创建桌面快捷方式：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\create_windows_shortcut.ps1
```

## 使用顺序

1. 在“扫描”页填写本地目标 URL。
2. 阅读目标下方的三步说明。
3. 首次使用选择“本机预检”并运行 Dry Run。
4. 检查目标、参数数量和命令预览。
5. 确认授权后使用“标准扫描”。
6. 在“输出与报告”页选择报告格式。
7. Payload 页只查询 Payload 资源，不会扫描目标。

## 测试

```powershell
py -3 dalfox_gui.pyw --self-test
py -3 dalfox_gui.pyw --ui-smoke-test
```

测试覆盖本地目标范围、公网目标拦截、敏感参数脱敏、
命令参数生成和后台 UI 构建。

## 许可证

本项目使用 MIT License。Dalfox 是独立项目，遵循其自身许可证。
