# STTool 渗透项目总控台

STTool 把现有渗透工具按“项目 / 运行实例”统一启动和监控。每次启动都建立独立运行目录；固定工具先收集资产，项目增量调度器在 AssetCommander 和 fscan 完成、资产稳定后先生成漏洞情报与安全验证候选，再启动本地 Codexx/Codex/Claude Agent。

## 启动

首次使用先安装项目依赖（TscanPlus DOM 自动化使用 Playwright，不需要额外下载 Chromium）：

```powershell
python -m pip install -e .
```

直接双击 `STTool.pyw` 不会出现 Python 黑色控制台。也可以双击 `start.bat`，或在当前目录运行：

```powershell
python .\main.py
```

即使用 `python .\main.py`，GUI 模式也会自动切换到 `pythonw.exe`；命令行窗口只会保留原本就已经打开的终端。Codexx/Codex Agent 是需要交互的终端标签页，不属于后台 Python 窗口。STTool 的 Agent 统一复用一个命名 Windows Terminal 窗口，每个项目批次使用独立标签页，可用 Ctrl+Tab 切换，避免任务栏堆积大量窗口。

不带参数就是 GUI。环境检测：

```powershell
python .\main.py --doctor
python .\main.py --list-tools
```

## 当前接入

- AssetCommander：默认启动，工作目录隔离到本次运行目录；通过源码状态机自动执行常用资产流程，不依赖屏幕坐标点击。
- semantic-recursive-dirscan：默认启动其工程 GUI，自动接收主目标、AssetCommander 域名/已确认 URL 和 fscan Web 服务，并使用自身工程状态继续未完成扫描。
- fscan、nuclei：项目创建时先执行一次初始扫描；随后自动调度器分别对新获准的 IP 和 URL 做去重增量补扫，每轮单独保留目标、日志和结果。
- vulnx：主漏洞情报引擎，项目创建时默认勾选；它是协调器管理的短任务阶段，不伪装为常驻 GUI/PID。按 CVE、产品和版本聚合 CVSS、EPSS、KEV、PoC 链接和 Nuclei 模板元数据，不执行 PoC，可在工具设置中编辑可执行文件路径。
- trickest/find-gh-poc：项目创建时默认勾选，是已有 CVE 的 GitHub 候选仓库补充，也是协调器管理的短任务阶段。它使用 GitHub GraphQL API，实际查询需要 GitHub Token；未配置时安全跳过，不会导致项目失败。Token 由当前 Windows 账户的 DPAPI 加密保存，只通过子进程环境传递，不进入项目文件、日志、命令行或启动脚本。结果仅作为不可信元数据写入 `results/find_gh_poc.json`，不会自动 clone 或执行。
- TscanPlus：每个运行实例使用独立 exe 名、WebView2 目录和私有 `config.db`，启动时清理历史项目目标、结果和 AWVS 报告。自动调度信息收集、资产探测、Web 指纹、域名/目录枚举、JsFinder、Swagger、WAF、POC、未授权、密码检测、DumpAll、AWVS 和 Nessus；AWVS/Nessus 只在连接测试明确成功后点击开始。
- Codexx CLI / Codex CLI / Claude CLI：三选一且必选；调度器在资产稳定后使用所选本地 Agent 启动首次全量批次，之后只对新代次资产启动增量批次。Agent 在命名 Windows Terminal/PowerShell 标签页中运行，多个项目和多个批次可通过 Ctrl+Tab 切换。

所有内置工具在新建项目时默认勾选。运行类型分为三类：AssetCommander、AI 路径发现、TscanPlus 和项目协调器属于常驻/监听组件；fscan、nuclei 的初始扫描属于一次性外部进程，后续增量批次由协调器串行启动；vulnx、find-gh-poc 属于协调器阶段短任务。运行实例会同时显示真实进程和协调器虚拟状态，但不会给短任务伪造 PID。

Agent 初始提示词采用证据驱动顺序：先读取项目状态，使用 Microsoft Playwright 查看界面、DOM、响应和网络请求，再按真实产品/版本证据检索厂商公告与 CVE；经源码审查的验证代码只能保存到本实例 `evidence/poc_review/<CVE>/`，执行时采用单目标、低并发、无持久化的最小影响验证，然后再联动固定扫描工具。手动执行 `codex --yolo` 时可复用 `docs/manual-codex-pentest-prompt.md`。

右上角的 **全局设置** 分成五块：**Codex / Codexx**、**Claude Agent**、**工具协作 AI**、**漏洞情报** 和 **调度方式**。Codex/Codexx 与 Claude 分别维护模型、推理强度和可选 Base URL，二者互不覆盖；Base URL 留空时继续使用对应 CLI 自身配置。项目脚本不会保存 Agent API Key，凭据仍由各 CLI 的登录或本机环境负责。仅在显式填写时，Codex/Codexx 使用 `OPENAI_BASE_URL`，Claude 使用 `ANTHROPIC_BASE_URL`。

保存全局设置后，工作流与调度配置会同步到全部现有工程，并通过每个实例的 `tool_data/coordinator/hot_settings.json` 热更新仍在运行的协调器。新增资产和下一批 AI 执行确认弹窗的处理方式、倒计时、弹窗开关，以及获准资产无新增等待、轮询、批次数、自动 Agent、停滞提醒、摘要开关、增量 fscan 线程和 C 段扩展策略会立即用于后续调度；尚未决策弹窗的截止时间会按新值重新计算。升级前已经运行的旧协调器会进行一次内部滚动更新，其他扫描工具和当前 Agent 保持运行。已经启动的外部扫描进程或 AI 会话不会被强制重启，其固定启动参数在后续增量任务、新实例或恢复时生效。选择历史项目不会反向覆盖全局设置。

工具协作 AI 用于工具间信息汇总、传递、去重和结果优化，可维护 OpenAI 兼容 Base URL、默认模型和 API Key。Base URL 默认是 `https://api.1314mc.net/v1`，普通设置保存在本机 `launcher_settings.json`；工具协作 API Key 和 GitHub Token 使用当前 Windows 账户的 DPAPI 加密后统一保存在 `launcher_secrets.dat`，不会写入项目配置、运行状态、启动脚本或日志。内置 AssetCommander 和 AI 路径发现默认使用工具协作 AI；自定义工具只有显式勾选“使用工具协作 AI”才会收到配置。

## 工具位置与自定义工具

“工具清单”支持直接维护本机工具：

- 选择内置工具后点击 **编辑**，AssetCommander 和 AI 路径发现选择工程目录，其他内置工具选择可执行文件。程序会自动推导配套脚本、虚拟环境和依赖路径。
- **重置内置位置** 会恢复仓库提供的默认位置，内置工具不能删除。
- **添加工具** 可以登记其他 GUI 或命令行工具；自定义工具可以继续编辑或删除。
- 自定义工具可以按行登记结果文件或目录，并选择是否使用工具协作 AI。
- 修改后会立即重新检测，并同步刷新“项目启动”中的可选工具。
- `find-gh-poc` 可在“工具清单 → 详情与结果”中直接配置 GitHub Token；该入口与“全局设置 → 漏洞情报”共用同一份 Windows DPAPI 加密值，修改后立即同步生效。

内置固定工具使用各自的源码适配器，因为其项目格式、结果格式和恢复规则已知。用户以后新增的任意工具只执行配置中的入口、参数、工作目录和“恢复时重启”规则；STTool 不会猜测它的按钮顺序，也不会把其他工具的结果强行写入未知格式。

配置保存在 STTool 根目录的 `tools.json`，该文件只属于当前电脑且已加入 `.gitignore`。换电脑后可重新选择各内置工具位置；需要迁移自定义工具时，可以单独带走这个文件并在新电脑上调整路径。

自定义工具参数和结果位置每行代表一个独立项目，可使用 `{project_name}`、`{target}`、`{target_host}`、`{target_domain}`、`{scope}`、`{run_dir}`、`{project_dir}`、`{tool_dir}` 和 `{st_root}` 占位符。工作目录同样支持这些占位符。会访问目标网络的工具应勾选“会发送网络请求”；需要在历史实例恢复时重新打开的常驻 GUI 应勾选“恢复时重启”。工具清单中双击工具或点击 **详情与结果**，可查看说明、选择历史运行实例，并一键打开已经生成或预期生成的结果位置；**打开工具面板** 会按该实例记录的 PID 及其子进程找到并置前现有窗口，不会重复启动工具。

fscan、nuclei 等一次性工具在详情页提供 **单独执行**。输入目标并再次确认授权后，只启动该工具，不创建项目、不启动 Agent，也不写入项目实例列表；状态和结果保存在 `standalone_runs/<工具>/<时间>/`。自定义工具勾选“允许单独执行”后也使用相同方式，其输入会替换参数中的 `{target}`、`{target_host}`、`{target_domain}` 和 `{scope}` 占位符。

## 项目与运行状态

项目名称是不会随目标、AI 服务商或线路变化的稳定人类可读标识，例如 `xinotter-api-regression`，不能填写目标 URL 或 AI Base URL。目标地址、工具协作 AI Base URL、Codex/Codexx Base URL 和 Claude Base URL 都是独立配置字段；修改这些地址只影响新运行配置，不会改变项目目录。新建项目会拒绝 HTTP/HTTPS URL 名称；旧版 URL 命名项目仍可原目录恢复，但从旧实例“新实例重跑”时会清空 URL 名称并要求重新填写稳定名称。不要直接移动或重命名旧运行目录，因为部分第三方工具状态可能保存绝对路径。

```text
projects/<稳定项目名>/project.json
projects/<稳定项目名>/runs/<时间戳-编号>/
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

- **恢复实例**：复用原运行目录，保留已有配置、进度和结果，只重启 AssetCommander、路径发现器、TscanPlus 等常驻工具以及 Agent。Codexx 使用 `codexx --yolo resume --last` 恢复当前目录最近一次会话，不会重复提交初始提示词；也不会重跑 fscan/nuclei 初始扫描，但恢复后的新获准资产仍会进入增量批次。
- **新实例重跑**：读取该历史实例的项目配置，在重新确认授权后创建一个全新的运行目录。
- **暂停工程**：结束该工程所有运行中实例的进程并保留运行目录和断点，之后可在原目录恢复。Agent 会按各运行目录识别其 PowerShell 根进程并结束 Codex/Codexx/Node 子进程，不会按进程名全局终止其他项目或用户手工启动的会话。
- **删除工程**：先暂停该工程的全部运行实例，再永久删除工程配置、运行状态、扫描结果、证据、日志、工具工作区及整个本地工程目录。删除前需要两次确认，删除后无法恢复。
- **准入与任务**：集中查看已允许、待确认、排除记录和已阻止资产；可人工添加、修改、允许、恢复或排除后续处理。被排除资产写入阻止清单，再次被工具发现也不会自动加入。窗口同时显示下一批 AI 执行确认历史和真实 AI 批次，可处理尚未决定的确认请求。排除只能阻止后续任务，不能撤销已经发送的请求或删除历史证据。

“恢复实例”和“新实例重跑”都要求本次重新勾选授权确认，避免历史授权被静默沿用。

每个新运行实例都会生成 `activity.log`。在“运行实例”中选择记录后点击 **项目日志**，或直接双击该记录，可以查看自动刷新的组件状态、当前步骤、等待原因、结果文件大小以及启动/退出/恢复/停止事件。组件表支持双击打开独立日志，合并展示该组件的状态 JSON、运行日志和结果入口；主日志支持滚动和“跟随最新”。

主窗口右上角提供 **全局搜索**。它可以跨项目和运行实例检索 IP、域名、URL、事件 ID、漏洞编号、工具名、错误与告警内容，并按项目及“日志 / 成果与报告 / 配置与状态”过滤。结果包含来源文件、行号、更新时间和前后文，可双击打开原始文件或直接打开对应运行目录；搜索在线程中执行，不会阻塞正在运行的项目。

## AssetCommander 自动流程

STTool 会向 AssetCommander 传入项目名、目标、授权范围和本次运行目录内的 `workflow_state.json`。自动流程按“初始化工程、FScan、OFA、真实 IP、IP 反查、去重、CIDR 裂变、对撞”执行，每一步完成后原子保存状态。若 AssetCommander 或 STTool 被意外结束，再次“恢复实例”会从未完成步骤继续，已完成步骤不会重复。

- 授权范围默认是 `*`，含义仅为主目标及本项目已提供或已发现资产全部放行，不会生成 `0.0.0.0/0` 或扫描整个互联网。
- `scope=*` 时 FScan 只从精确主目标开始；显式 IP/CIDR 范围仍按该范围执行。
- C 段扩展开关默认关闭；关闭时 AssetCommander 不执行显式 CIDR 或 `scope=*` 派生 `/24` 的裂变。开启后只会执行已授权网段的资产发现，新主机仍须通过准入弹窗或倒计时默认决策，才会进入后续工具。
- IP 反查得到的域名会过滤回当前项目域名范围。
- 业务关键词可通过 OpenAI Responses 兼容接口生成；使用 `OPENAI_API_KEY`，并可通过 `OPENAI_BASE_URL`、`OPENAI_MODEL` 配置，未配置或请求失败时使用本地关键词。
- 对撞默认保留原端口，并启用 80、443 和非标准端口；关闭绝对路径、WAF 绕过和强制 SNI，并发数为 150。

这里采用的是源码级状态机。pywinauto/RPA 仅适合无法修改源码的第三方窗口兜底；AssetCommander 本身不使用坐标 RPA，以避免分辨率、弹窗和程序重启导致流程失效。

## 固定工具结果推送

AssetCommander 每次保存工程时会原子更新本次运行目录下的 `results/asset_commander_assets.json`。在去重和 CIDR 处理后、collision 开始前执行 `publish_assets`，写入 `asset_handoff.status=ready`；路径发现和 TscanPlus 此时立即接收稳定资产，不再等待 collision 完成。collision 结束后继续更新最终导出，路径发现会接收新增 URL，Tscan 不重复提交已经运行的同批任务。`results/fscan.txt` 仅导入明确识别为 HTTP/HTTPS 的 Web 服务端口；裸 IP 和 CIDR 不会作为目录扫描 URL。路径发现工程设置中的“目标启动间隔(秒)”默认是 8 秒，由所有并发 worker 共同遵守，避免多个目标同时突发启动。

路径发现器的 `projects/<项目>/project.json` 和各目标 `runtime_state.json` 是扫描进度的权威记录。“恢复实例”复用这些文件，已完成目标不重复，失败目标不会被自动循环重试，新到达的待运行目标会在当前批次结束后进入下一批。恢复时会刷新内置适配器代码，但保留运行副本中的项目、字典、配置、结果和断点。

STTool 不读取或覆盖 Codexx、Codex、Claude CLI 的登录凭据；仅在全局设置中明确填写时，为所选 Agent 附加独立的模型、推理强度和 Base URL。工具协作 API Key 与 GitHub Token 使用 Windows DPAPI 加密保存在本机；路径发现器的运行副本会清空 `config.json` 中的 `ai_api_key`，仅向明确启用工具协作 AI 的子进程注入 `OPENAI_API_KEY`。CLI 预检通过只代表命令可用；运行实例中的 Agent 状态才代表该项目批次的本地进程是否仍在线。


## 增量资产总线与 Agent 批次

新增主机确认弹窗不会暂停现有扫描和报告整理；待确认资产不会进入 fscan、Tscan、dirsearch 或 Agent。即使主界面关闭，协调器仍会在倒计时结束后按当前全局热配置的默认动作处理，避免流程永久卡住。

各控制项按顺序生效，并非重复开关：授权范围先决定资产是否允许测试；新资产准入策略决定新主机是否进入后续队列；“获准资产无新增等待”从最后一次允许新资产开始计时，用于合并零散发现；待处理资产达到阈值时，再确认是否启动下一批 Codex/Claude；最后仍受最大 AI 执行次数限制。最大次数只统计成功完成的 AI 执行，线路或模型请求失败会保留为失败记录但不占成功额度；同一线路连续失败 3 次后会暂停自动重试，修改设置或恢复项目后可再次尝试。弹窗倒计时与无新增等待不会并行争抢同一个决定：资产获准后才开始后者。资产确认弹窗到期后由界面提交选择，协调器额外保留短暂宽限作为兜底；AI 执行确认到期由协调器统一决定，避免重复启动。

- `tool_data/asset_bus/assets.json` 是单写者资产总线，记录 IP、域名、端点、URL、来源和首次出现代次。
- AssetCommander、fscan、路径发现和 TscanPlus 的结构化结果会去重后进入总线；Tscan 枚举的新 IP/域名会回流 AssetCommander 资产池并使用历史任务键做增量对撞。
- 首个 Agent 批次必须等待 AssetCommander 完成、fscan 结束且资产连续 20 秒无新增。Agent 提示词必须读取 fscan 全量输出，对每个 Web URL/端口逐个检查。
- 每批保存在 `agent_batches/<批次>/`，包含提示词、启动脚本、PID、真实退出状态和完成时间；启动脚本只向 CLI 传递读取 `prompt.txt` 的短引导，避免 Windows 命令行长度限制。每个 Agent 启动脚本只能消费一次启动令牌；暂停项目时会禁用已有启动脚本并保留备份，防止 Windows Terminal 在重启或恢复旧标签页后重新执行已暂停批次。失败批次按 60 秒、5 分钟、15 分钟退避重试；项目日志可双击“项目增量调度/Agent”查看。
- `risk_summary.md` 随资产代次刷新；配置工具协作 AI 时优先尝试 Responses API，不兼容时回退 Chat Completions。超大资产摘要只向 AI 发送有界的头尾证据片段，完整本地摘要始终保留；单个协议尝试使用 20 秒超时，避免阻塞 Agent 启动数分钟。
- `vulnerability_intel.md`、`results/vulnerability_intel.json` 和 `results/find_gh_poc.json` 在资产稳定、Agent 启动前按所选工具生成，记录产品/版本证据、CVE、KEV、模板和 GitHub PoC 候选。它们会按输入指纹和资产代次缓存，恢复工程时不重复联网查询；运行实例中可双击对应虚拟组件打开可读状态和结果文件。
- PoC URL 始终按不可信元数据处理，不自动 clone 或执行。写文件、创建账号、反弹 Shell、抓凭据、持久化和横向移动不属于自动情报阶段，后续若实现 Post-Exploitation 必须独立默认关闭并要求人工审批。


## 项目成果入口

“运行实例”页面提供独立的 **项目成果** 按钮，与“项目日志”分开。成果窗口只展示面向人的报告、问题、资产和扫描成果，隐藏内部状态与 Agent 日志；单击上方成果即可在下方查看可读预览，其中的 URL 可直接用默认浏览器打开。fscan、nuclei 和目录扫描会按目标/批次分别显示，Tscan 数据库会转换为可读线索。大型资产清单在预览中自动折叠，原始文件仍可一键打开。


### Human-readable per-tool logs

Double-clicking a project tool now opens a tool-specific view instead of placing raw state JSON at the top of the window. The view shows a readable runtime overview first, followed by only that tool's own logs. For AI path discovery this includes synchronized targets, queued targets, AssetCommander handoff state, current URL/depth, completed parent paths, pending queue size and key findings.

Raw JSON is still available through the **Open raw state** button for debugging, but it no longer dominates the normal operator view.
