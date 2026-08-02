# STTool 渗透项目总控台

STTool 把现有渗透工具按“项目 / 运行实例”统一启动和监控。每次启动都建立独立运行目录；固定工具先收集资产，项目增量调度器在 AssetCommander 和 fscan 完成、资产稳定后再启动本地 Codexx/Codex Agent。

## 启动

首次使用先安装项目依赖（TscanPlus DOM 自动化使用 Playwright，不需要额外下载 Chromium）：

```powershell
python -m pip install -e .
```

直接双击 `STTool.pyw` 不会出现 Python 黑色控制台。也可以双击 `start.bat`，或在当前目录运行：

```powershell
python .\main.py
```

即使用 `python .\main.py`，GUI 模式也会自动切换到 `pythonw.exe`；命令行窗口只会保留原本就已经打开的终端。Codexx/Codex Agent 是需要交互的独立终端，不属于后台 Python 窗口。

不带参数就是 GUI。环境检测：

```powershell
python .\main.py --doctor
python .\main.py --list-tools
```

## 当前接入

- AssetCommander：默认启动，工作目录隔离到本次运行目录；通过源码状态机自动执行常用资产流程，不依赖屏幕坐标点击。
- semantic-recursive-dirscan：默认启动其工程 GUI，自动接收主目标、AssetCommander 域名/已确认 URL 和 fscan Web 服务，并使用自身工程状态继续未完成扫描。
- fscan、nuclei：自动发包类工具，默认不勾选。
- TscanPlus：每个运行实例使用独立 exe 名、WebView2 目录和私有 `config.db`，启动时清理历史项目目标、结果和 AWVS 报告。自动调度信息收集、资产探测、Web 指纹、域名/目录枚举、JsFinder、Swagger、WAF、POC、未授权、密码检测、DumpAll、AWVS 和 Nessus；AWVS/Nessus 只在连接测试明确成功后点击开始。
- Codexx CLI / Codex CLI：二选一且必选；调度器在资产稳定后以 `codexx --yolo` 或 `codex --yolo` 启动首次全量批次，之后只对新代次资产启动增量批次，不覆盖 CLI 自身模型、线路或凭据。

Agent 初始提示词采用证据驱动顺序：先读取项目状态，使用 Microsoft Playwright 查看界面、DOM、响应和网络请求，再按真实产品/版本证据检索厂商公告与 CVE；经源码审查的验证代码只能保存到本实例 `evidence/poc_review/<CVE>/`，执行时采用单目标、低并发、无持久化的最小影响验证，然后再联动固定扫描工具。手动执行 `codex --yolo` 时可复用 `docs/manual-codex-pentest-prompt.md`。

右上角的 **工具协作 AI 设置** 用于工具间信息汇总、传递、去重和结果优化，可维护 OpenAI 兼容 Base URL、默认模型和 API Key。Base URL 默认是 `https://api.1314mc.net/v1`，普通设置保存在本机 `launcher_settings.json`；API Key 使用当前 Windows 账户的 DPAPI 加密后单独保存在 `launcher_secrets.dat`，不会写入项目配置、运行状态、启动脚本或日志。内置 AssetCommander 和 AI 路径发现默认使用这套配置；自定义工具只有显式勾选“使用工具协作 AI”才会收到配置。Codexx/Codex 始终使用各自本地配置。

## 工具位置与自定义工具

“工具清单”支持直接维护本机工具：

- 选择内置工具后点击 **编辑**，AssetCommander 和 AI 路径发现选择工程目录，其他内置工具选择可执行文件。程序会自动推导配套脚本、虚拟环境和依赖路径。
- **重置内置位置** 会恢复仓库提供的默认位置，内置工具不能删除。
- **添加工具** 可以登记其他 GUI 或命令行工具；自定义工具可以继续编辑或删除。
- 自定义工具可以按行登记结果文件或目录，并选择是否使用工具协作 AI。
- 修改后会立即重新检测，并同步刷新“项目启动”中的可选工具。

内置固定工具使用各自的源码适配器，因为其项目格式、结果格式和恢复规则已知。用户以后新增的任意工具只执行配置中的入口、参数、工作目录和“恢复时重启”规则；STTool 不会猜测它的按钮顺序，也不会把其他工具的结果强行写入未知格式。

配置保存在 STTool 根目录的 `tools.json`，该文件只属于当前电脑且已加入 `.gitignore`。换电脑后可重新选择各内置工具位置；需要迁移自定义工具时，可以单独带走这个文件并在新电脑上调整路径。

自定义工具参数和结果位置每行代表一个独立项目，可使用 `{project_name}`、`{target}`、`{target_host}`、`{target_domain}`、`{scope}`、`{run_dir}`、`{project_dir}`、`{tool_dir}` 和 `{st_root}` 占位符。工作目录同样支持这些占位符。会访问目标网络的工具应勾选“会发送网络请求”；需要在历史实例恢复时重新打开的常驻 GUI 应勾选“恢复时重启”。工具清单中双击工具或点击 **详情与结果**，可查看说明、选择历史运行实例，并一键打开已经生成或预期生成的结果位置；**打开工具面板** 会按该实例记录的 PID 及其子进程找到并置前现有窗口，不会重复启动工具。

fscan、nuclei 等一次性工具在详情页提供 **单独执行**。输入目标并再次确认授权后，只启动该工具，不创建项目、不启动 Agent，也不写入项目实例列表；状态和结果保存在 `standalone_runs/<工具>/<时间>/`。自定义工具勾选“允许单独执行”后也使用相同方式，其输入会替换参数中的 `{target}`、`{target_host}`、`{target_domain}` 和 `{scope}` 占位符。

## 项目与运行状态

```text
projects/<项目>/project.json
projects/<项目>/runs/<时间戳-编号>/
  agent_prompt.txt
  agent_batches/
  risk_summary.md
  project.json
  run.json
  scope.txt
  results/
  tool_data/
    asset_bus/assets.json
    coordinator/state.json
```

同一项目正在运行时可以再次点击“启动新实例”，新实例使用新的运行目录。启动过程有全局独占锁；工具和 Agent 全部通过预检后才会启动，任何组件启动失败都会结束本次已经拉起的进程并把运行标记为失败。

“运行实例”表中的每一行都是一次历史运行记录，程序异常结束后记录和产物仍会保留。选中一行后可以使用：

- **恢复实例**：复用原运行目录，保留已有配置、进度和结果，只重启 AssetCommander、路径发现器、TscanPlus 等常驻工具以及 Agent。Codexx 使用 `codexx --yolo resume --last` 恢复当前目录最近一次会话，不会重复提交初始提示词；也不会自动重跑一次性的 fscan/nuclei。
- **新实例重跑**：读取该历史实例的项目配置，在重新确认授权后创建一个全新的运行目录。

两种操作都要求本次重新勾选授权确认，避免历史授权被静默沿用。

每个新运行实例都会生成 `activity.log`。在“运行实例”中选择记录后点击 **项目日志**，或直接双击该记录，可以查看自动刷新的组件状态、当前步骤、等待原因、结果文件大小以及启动/退出/恢复/停止事件。组件表支持双击打开独立日志，合并展示该组件的状态 JSON、运行日志和结果入口；主日志支持滚动和“跟随最新”。

## AssetCommander 自动流程

STTool 会向 AssetCommander 传入项目名、目标、授权范围和本次运行目录内的 `workflow_state.json`。自动流程按“初始化工程、FScan、OFA、真实 IP、IP 反查、去重、CIDR 裂变、对撞”执行，每一步完成后原子保存状态。若 AssetCommander 或 STTool 被意外结束，再次“恢复实例”会从未完成步骤继续，已完成步骤不会重复。

- 授权范围默认是 `*`，含义仅为主目标及本项目已提供或已发现资产全部放行，不会生成 `0.0.0.0/0` 或扫描整个互联网。
- `scope=*` 时 FScan 只从精确主目标开始；显式 IP/CIDR 范围仍按该范围执行。
- C 段裂变在显式 CIDR 授权下按该网段执行；`scope=*` 时只会根据项目内已提供/已发现 IPv4 派生对应 `/24`，不代表扫描任意互联网地址。
- IP 反查得到的域名会过滤回当前项目域名范围。
- 业务关键词可通过 OpenAI Responses 兼容接口生成；使用 `OPENAI_API_KEY`，并可通过 `OPENAI_BASE_URL`、`OPENAI_MODEL` 配置，未配置或请求失败时使用本地关键词。
- 对撞默认保留原端口，并启用 80、443 和非标准端口；关闭绝对路径、WAF 绕过和强制 SNI，并发数为 150。

这里采用的是源码级状态机。pywinauto/RPA 仅适合无法修改源码的第三方窗口兜底；AssetCommander 本身不使用坐标 RPA，以避免分辨率、弹窗和程序重启导致流程失效。

## 固定工具结果推送

AssetCommander 每次保存工程时会原子更新本次运行目录下的 `results/asset_commander_assets.json`。在去重和 CIDR 处理后、collision 开始前执行 `publish_assets`，写入 `asset_handoff.status=ready`；路径发现和 TscanPlus 此时立即接收稳定资产，不再等待 collision 完成。collision 结束后继续更新最终导出，路径发现会接收新增 URL，Tscan 不重复提交已经运行的同批任务。`results/fscan.txt` 仅导入明确识别为 HTTP/HTTPS 的 Web 服务端口；裸 IP 和 CIDR 不会作为目录扫描 URL。路径发现工程设置中的“目标启动间隔(秒)”默认是 8 秒，由所有并发 worker 共同遵守，避免多个目标同时突发启动。

路径发现器的 `projects/<项目>/project.json` 和各目标 `runtime_state.json` 是扫描进度的权威记录。“恢复实例”复用这些文件，已完成目标不重复，失败目标不会被自动循环重试，新到达的待运行目标会在当前批次结束后进入下一批。恢复时会刷新内置适配器代码，但保留运行副本中的项目、字典、配置、结果和断点。

STTool 不读取或覆盖 Codexx、Codex 的 AI 配置，它们直接使用对应 CLI 已有的模型、线路和安全凭据。工具协作 API Key 使用 Windows DPAPI 加密保存在本机；路径发现器的运行副本会清空 `config.json` 中的 `ai_api_key`，仅向明确启用工具协作 AI 的子进程注入 `OPENAI_API_KEY`。`Codexx: 已安装并登录` 或 `Codex: 已安装并登录` 代表对应 CLI 预检通过；运行实例中的 Agent 状态代表该次本地进程是否仍在线。


## 增量资产总线与 Agent 批次

- `tool_data/asset_bus/assets.json` 是单写者资产总线，记录 IP、域名、端点、URL、来源和首次出现代次。
- AssetCommander、fscan、路径发现和 TscanPlus 的结构化结果会去重后进入总线；Tscan 枚举的新 IP/域名会回流 AssetCommander 资产池并使用历史任务键做增量对撞。
- 首个 Agent 批次必须等待 AssetCommander 完成、fscan 结束且资产连续 20 秒无新增。Agent 提示词必须读取 fscan 全量输出，对每个 Web URL/端口逐个检查。
- 每批保存在 `agent_batches/<批次>/`，包含提示词、启动脚本、PID 和完成时间；项目日志可双击“项目增量调度/Agent”查看。
- `risk_summary.md` 随资产代次刷新；配置工具协作 AI 时优先尝试 Responses API，不兼容时回退 Chat Completions。
