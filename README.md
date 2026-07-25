# STTool 渗透项目总控台

STTool 把现有渗透工具按“项目 / 运行实例”统一启动和监控。每次点击启动都会建立独立运行目录，并且必须同时启动一个 Codex CLI 或 Claude CLI Agent。

## 启动

直接双击 `STTool.pyw` 不会出现 Python 黑色控制台。也可以双击 `start.bat`，或在当前目录运行：

```powershell
python .\main.py
```

即使用 `python .\main.py`，GUI 模式也会自动切换到 `pythonw.exe`；命令行窗口只会保留原本就已经打开的终端。Codex/Claude Agent 是需要交互的独立终端，不属于后台 Python 窗口。

不带参数就是 GUI。环境检测：

```powershell
python .\main.py --doctor
python .\main.py --list-tools
```

## 当前接入

- AssetCommander：默认启动，工作目录隔离到本次运行目录。
- semantic-recursive-dirscan：默认启动其工程 GUI。
- fscan、nuclei：自动发包类工具，默认不勾选。
- TscanPlus、POC 工具箱：可选 GUI。
- Codex CLI / Claude CLI：二选一且必选，项目提示词自动作为第一条消息输入。

## 项目与运行状态

```text
projects/<项目>/project.json
projects/<项目>/runs/<时间戳-编号>/
  agent_prompt.txt
  launch_agent.ps1
  project.json
  run.json
  scope.txt
  results/
  tool_data/
```

同一项目正在运行时可以再次点击“启动新实例”，新实例使用新的运行目录。启动过程有全局独占锁；工具和 Agent 全部通过预检后才会启动，任何组件启动失败都会结束本次已经拉起的进程并把运行标记为失败。

STTool 不保存 API Key。Codex 和 Claude 直接使用对应 CLI 已有的安全凭据。路径发现器的运行副本会清空 `config.json` 中的 `ai_api_key`，仅向该子进程注入 `OPENAI_API_KEY`。`Codex: 已安装并登录` 代表 CLI 预检通过；运行实例中的 `Codex Agent:运行` 代表该次 Agent 进程仍在线。
