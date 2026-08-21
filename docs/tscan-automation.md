# TscanPlus 自动化调查与接入

## 技术结论

- 版本：TscanPlus / 无影 v3.3.9。
- 框架：Wails 桌面容器 + Microsoft Edge WebView2，页面地址为 `http://wails.localhost/`。
- 普通 UI Automation 只能看到 WebView2 容器，不能稳定看到内部 DOM。
- 稳定方案：启动时临时通过 WebView2 `AdditionalBrowserArguments` 策略打开本机随机 CDP 端口，启动后立即恢复原策略，然后用 Playwright 按 DOM 控件操作，不依赖坐标。

## 功能地图

1. **项目管理**：新建/删除/刷新项目，备份或重置数据库。
2. **信息收集**：域名、单位、IP、ICP、子域名、历史 IP、IP 反查、分支/投资/版权/APP/小程序等。
3. **资产探测**：端口扫描、Web 指纹、域名枚举、目录枚举、JsFinder、Swagger、WAF 识别。
4. **漏洞检测**：PoC 检测、密码破解、未授权检测、Awvs、Nessus。
5. **轻武器库**：水洞专用、DumpAll、PoC 生成、Repeater、JwtCrack、小程序反编译、代理池、40xBypass、Host 碰撞、ICP/IP 查询、幽灵 Bits。
6. **AK 管理 / 空间测绘**：搜索引擎 API 凭据与资产查询。
7. **编码转换 / 红队 Wiki / 辅助工具**：反弹 Shell、红队命令、下载命令、WebShell、CS 上线、Java 命令编码、资产分拣、数据处理、密码生成/查询、杀软查询、提权辅助。
8. **快捷启动**：本地工具登记、分类和启动。

结构化功能地图和 293 个 Wails 后端方法清单见 `tscan_ui_inventory.json`。

## STTool 默认自动化流程

当前默认入口使用同版本的 `TscanClient` 命令行后端；也可以在全局设置的“调度方式”页切换为
`GUI 自动化`。不再依赖 TscanPlus
图形版的 WebView2/CDP 或鼠标点击。TscanClient 没有可视化窗口，也没有
TscanPlus 页面里的右键菜单；STTool 自己的成果页、右键 AI、资产准入、
暂停恢复和全局搜索仍然正常保留。

后台 TscanClient 目前由 STTool 分批调用 `port`、`url`、`poc` 三个阶段：

- 每个获准资产总线代次单独保存到 `tool_data/tscan/client/batch-*/`；
- 每轮有独立的 `port.txt`、`url.txt`、`poc.txt` 和日志，成果页会逐轮显示；
- 目录和 JS 继续由现有 AI 路径发现工具处理，避免重复扫描；
- 密码审计继续由 PassHack/凭据审批链处理，不会因为切换 CLI 自动爆破；
- 代理从 STTool 工具网络设置传入 TscanClient 的 `-proxy` 参数。

如果需要 TscanPlus 的可视化页面、右键菜单或其未接入的功能，应使用项目
目录中保留的 GUI 版本手动打开；这不是后台 TscanClient 的启动标志。
切换为 GUI 自动化后，新启动或恢复的实例才会使用 GUI；已经运行的进程不会被设置修改强制重启。

`sttool/tscan_automation.py` 会：

1. 用 Tscan 原目录作为 CWD 启动 EXE。
2. 临时打开仅监听 `127.0.0.1` 的随机 CDP 端口，连接后恢复系统策略。
3. 保持 Tscan 窗口可见，等待 AssetCommander 的 `workflow_state.json` 完成并读取结构化资产导出。
4. `scope=*` 接受主目标和本项目已发现资产；显式域名或 CIDR 范围仍进行过滤。`*` 不生成无界地址空间。
5. 在“信息收集”中载入主目标，开启端口扫描和 Web 指纹并点击“查询”。
6. 在“资产探测”中批量载入域名和 IP，选择 Web 模式、并发 100、端口指纹并点击 `Scan`。
7. 在“POC 检测”中载入规范化 HTTP/HTTPS URL，保持 POC 指纹匹配，只选择界面中实际可用的 POC 分类并点击 `Check`。
8. 在“密码破解”中仅载入已回传的 IP，保持指纹识别和“仅破解一个账户”，点击 `Crack`；不会自动开启命令执行。
9. 在 AWVS 中导入规范化 URL，确认本地 API 地址和 API Key 已配置后先做连接测试，再点击“开始扫描”。凭据值不会写入状态文件或日志。
10. 在 Nessus 中导入域名和 IP，确认本地 API、Access Key 和 Secret Key 已配置后先做连接测试，再点击“开始扫描”。凭据值不会写入状态文件或日志。
11. PID、CDP 端口、等待状态、每个阶段和错误写入 `tool_data/tscan/state.json`。若启动器异常结束但 GUI 仍在，会优先重新接管原 PID/CDP，而不是重复打开窗口。
12. 启动器常驻等待 Tscan 退出，STTool 停止运行时可终止整个进程树。

Cookie、OOB、代理、命令执行、未授权检测和许可证不可用模块不会被自动配置，仍可从“打开工具面板”进入 Tscan 手动操作。
