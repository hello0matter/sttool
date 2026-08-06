from __future__ import annotations

from pathlib import Path


HELP_FILENAME = "STTool使用说明.txt"


def build_help_text() -> str:
    return """STTool 使用说明（中文详细版）

一、这个软件是做什么的
STTool 是一个“项目化、可恢复、可增量”的授权安全测试总控台。它会把资产发现、端口探测、目录发现、漏洞线索、AI 验证批次、项目日志和成果目录统一放到同一个项目运行实例里，方便中途退出后继续。

二、主界面三个页签
1. 项目启动
   - 用来填写项目名称、主要目标、授权范围、AI Agent 类型和本次要勾选的工具。
2. 运行实例
   - 用来看所有项目运行实例、恢复旧实例、停止实例、查看项目日志、查看项目成果。
3. 工具清单
   - 用来管理固定工具的可执行文件、参数、工作目录、说明和是否默认勾选。

三、右上角按钮
1. ？ 使用说明
   - 打开当前这份 TXT 说明文档。
2. 全局设置
   - 打开全局配置窗口。
   - 这里主要配置：
     - 工具协作 AI 的 API Base URL、模型、API Key；
     - Codex/Codexx 的模型、推理强度、路由地址；
     - Claude 的模型、推理强度、路由地址；
     - GitHub Token（给 find-gh-poc 这类需要 GitHub API 的工具用）；
     - 工作方式选项，例如是否等待 AssetCommander、是否等待 fscan、最大 Agent 批次等。

四、项目名称和目标怎么理解
1. 项目名称
   - 必须是稳定名称。
   - 不建议把 URL、本次模型地址、某条 AI 路线直接当项目名称。
   - 因为 URL、AI 路线以后会变，项目名称应该固定，方便恢复。
2. 主要目标
   - 可以是 URL、域名或 IP。
3. 授权范围
   - 常见写法是 *、单个域名、多个域名、单个 IP、CIDR。
   - 如果写 *，表示项目逻辑按“默认全授权”处理，工具会尽量放开联动。

五、运行实例和“历史项目/历史实例”
1. 一个项目下面可以有多个运行实例。
2. 每次点击“启动新实例”，都会创建一个新的 runs\\时间戳-序号 目录。
3. 这就是“历史项目可以重新启动”的基础：
   - 你可以选中旧实例做“恢复”；
   - 也可以“载入为新实例重跑”；
   - 即使程序被意外关闭，只要运行目录和状态文件还在，就能尽量恢复。

六、项目目录结构（最重要）
每个项目通常在：
projects\\项目名\\runs\\运行实例ID\\

常见目录与文件如下：

1. activity.log
   - 项目总日志。
   - 记录工具启动、等待、完成、失败、资产回流、Agent 批次启动等全过程。

2. project.json
   - 项目配置快照。
   - 记录项目名称、目标、授权范围、AI 选择、勾选工具等。

3. run.json
   - 当前运行实例的状态快照。
   - 包括实例状态、进程记录、恢复次数、工具列表等。

4. scope.txt
   - 当前实例使用的授权范围文本。

5. agent_prompt.txt
   - 给 Agent 的基础提示词。

6. risk_summary.md
   - 面向机器和高级操作者的“风险底稿”。
   - 里面会放更多资产、端点、工具线索和汇总证据。
   - 这个文件可能非常长，不适合直接当最终报告给人看。

7. pentest_report.md
   - 面向人的正式渗透测试报告（当前版本为自动汇总版）。
   - 重点展示已确认问题、待验证线索、覆盖矩阵、关键证据路径。

8. pentest_report.txt
   - pentest_report.md 的同内容 TXT 版本。

9. findings.json / findings.md
   - findings.json 是“问题管理”窗口保存的结构化问题源文件。
   - findings.md 是自动生成的人类可读版本。
   - 已确认问题必须同时有复现过程和证据；自动化线索应先保持为待验证。

10. cve_triage.md
    - CVE 快速排查结果。

11. vulnerability_intel.md / vulnerability_intel.json
    - 漏洞情报、CVE 候选、PoC 候选、工具状态等结构化输出。

12. results\\
    - 放最终结果文件，比如：
      - fscan.txt
      - nuclei.txt
      - asset_commander_assets.json
      - vulnerability_intel.json
      - find_gh_poc.json

13. evidence\\
    - 存放证据抓取内容，比如 HTTP 请求响应、截图、Playwright 取证、批量探测记录等。

14. tool_data\\
    - 每个固定工具自己的运行状态、桥接文件、数据库、临时目录通常都在这里。

15. component_logs\\
    - 从项目总日志里按工具切出来的“单工具日志”。

16. agent_batches\\
    - 每个 AI Agent 批次一个子目录。
    - 里面通常有 prompt、batch.json、批次工作文件、退出状态等。

17. scripts\\
    - 运行时生成或调用的脚本。

七、常见英文文件/目录名是什么意思
1. risk_summary.md
   - 风险摘要底稿，不是最终人类报告。
2. pentest_report.md
   - 渗透测试报告。
3. findings.md
   - 问题清单。
4. cve_triage.md
   - CVE 快速筛查。
5. vulnerability_intel.json
   - 结构化漏洞情报。
6. find_gh_poc.json
   - GitHub PoC 搜索结果。
7. tool_data
   - 工具运行数据。
8. evidence
   - 证据目录。
9. component_logs
   - 单工具日志。
10. agent_batches
    - Agent 批次目录。

八、固定工具说明
1. AssetCommander
   - 资产发现总控工具。
   - 负责资产采集、碰撞、去重、归并、可恢复工作流、阶段状态保存。

2. OneForAll / OFA
   - 子域名枚举。
   - 常由 AssetCommander 内部调用。

3. fscan
   - 基础端口和服务探测。
   - 输出开放端口、服务信息、站点入口等。

4. nuclei
   - 模板扫描和指纹识别。
   - 适合做信息级线索、配置级线索和已知模板检测。

5. semantic-recursive-dirscan
   - AI 路径发现工具。
   - 负责递归发现目录、接口、资源和下一层入口。

6. TscanPlus
   - 联动型工具。
   - 可能包含信息收集、目录、POC、未授权、密码检测、AWVS、Nessus 等模块。

7. AWVS
   - Web 自动化扫描器。

8. Nessus
   - 综合扫描器。

9. vulnx
   - 做漏洞情报/CVE/公开信息辅助分析。

10. find-gh-poc
    - 搜索 GitHub 上的 PoC 元数据。
    - 通常需要 GitHub Token。

11. Codex / Codexx / Claude
    - 作为 AI Agent 使用。
    - 负责阅读当前项目状态、取证、验证候选、补充风险分析和生成文本成果。

九、完整工作流（人话版）
1. 创建项目并填写目标；
2. 创建新的运行实例目录；
3. 启动固定工具；
4. AssetCommander 先做资产收集、碰撞、去重；
5. fscan、nuclei、路径发现等陆续回传结果；
6. 资产总线统一吸收这些新增资产；
7. 项目协调器判断：
   - AssetCommander 是否完成；
   - fscan 是否完成；
   - 资产是否进入安静窗口；
8. 满足条件后再启动 Agent 批次；
9. Agent 逐批验证 Web 资产、读取结果文件、生成线索；
10. 输出 risk_summary.md 和 pentest_report.md；
11. 中途退出后可恢复，再继续增量执行。

十、常见状态翻译
1. pending
   - 待运行。
2. not_started
   - 未开始。
3. prepared
   - 已准备。
4. submitted
   - 已提交启动。
5. running
   - 运行中。
6. monitoring
   - 监控中。
7. waiting_assets
   - 等待资产回传。
8. waiting_configuration
   - 等待配置完成。
9. standby
   - 待命。
10. suspected_stalled
    - 疑似卡住。
11. stalled
    - 已卡住。
12. completed
    - 已完成。
13. failed
    - 失败。
14. stopped
    - 已停止。
15. unavailable
    - 不可用。
16. skipped
    - 已跳过。
17. skipped_no_token
    - 因缺少 Token 跳过。
18. metadata_only
    - 只收集元数据，不直接做利用。
19. acknowledged
    - 已确认收到/已登记。
20. idle
    - 空闲。

十一、为什么有些工具显示“运行中”，但窗口没动
可能原因：
1. 进程虽然还活着，但在等待上游资产；
2. 已经跑完主体任务，但窗口保留；
3. 进程结束了，但状态文件还没刷新；
4. 工具自身卡住、网络等待、数据库锁住；
5. 子进程退出，但父进程还没清理。

因此判断是否真的卡死，不要只看窗口，要同时看：
1. 项目日志；
2. 单工具日志；
3. tool_data 里的状态文件；
4. CPU/内存是否持续变化；
5. 结果文件时间戳是否更新。

十二、项目日志和单工具日志的区别
1. 项目日志
   - 看整个项目当前在干什么。
   - 适合判断是否在等待 AssetCommander、等待 fscan、等待资产安静窗口、等待 Agent 重试。
2. 单工具日志
   - 看某一个工具自己的日志。
   - 比如只看 fscan、只看 AssetCommander、只看 TscanPlus。
3. 自动跟随最新日志
   - 默认开启。
   - 如果你只是盯实时输出，窗口会自动保持在最后一行。
4. 如何暂停自动跟随
   - 鼠标滚轮上翻/下翻；
   - 按 PageUp / PageDown；
   - 拖动右侧滚动条。
   - 这些动作都会自动关闭“自动跟随最新日志”，防止刷新把你拉走。
5. 回到底部
   - 点“回到底部”按钮，可以立刻跳回最新日志。
   - 同时会恢复自动跟随。
6. 为什么现在不会老是自动回弹
   - 当你已经手动离开底部去翻旧日志时，刷新会尽量保持当前位置，不再强行把视图抢走。

十三、项目成果窗口怎么看
1. 优先看 pentest_report.md
   - 这是给人看的。
   - 报告内包含修复与复核优先级表：P0 最优先，P1 次之，P2/P3 为近期整改或持续观察。
2. 点击“问题管理”
   - 打开结构化问题库。
   - findings.json 是机器可读源文件，findings.md 是人类可读版本。
   - 状态可选“已确认、待验证、已排除”。
   - “已确认”必须填写复现过程和证据，避免把工具误报直接写成漏洞。
3. 点击“导出报告”
   - 把当前 pentest_report.md 或 TXT 报告复制到你选择的位置。
4. 点击“打开证据目录”
   - 直接打开当前实例的 evidence 目录，方便补充截图、请求响应和人工取证文件。
5. 再看 cve_triage.md / vulnerability_intel.md
   - 这是辅助判断。
6. 最后再看 risk_summary.md
   - 这是全量底稿，不适合直接对外。

十四、恢复逻辑
1. 如果程序被关闭，只要 runs\\实例ID 还在，就尽量可恢复。
2. 恢复时会检查：
   - 状态文件是否存在；
   - PID 是否还活着；
   - 这个 PID 是否属于当前实例；
   - 工具是否需要重启。
3. 如果旧 PID 已失效，工具可能重新启动或进入“待恢复”状态。

十五、什么时候适合“新实例重跑”
1. 你想保留历史实例，又重新完整跑一轮；
2. 目标资产、授权边界、提示词明显变了；
3. 旧实例结果太杂，不适合继续增量。

十六、什么时候适合“恢复”
1. 机器重启；
2. 软件被误关；
3. 工具窗口意外退出；
4. 你想继续原来的运行目录和原来的进度。

十七、工具设置页是干什么的
1. 编辑每个固定工具的路径；
2. 编辑参数；
3. 编辑工作目录；
4. 编辑说明；
5. 控制是否默认勾选；
6. 控制是否允许单独执行；
7. 这些配置会在实际工作中生效，不只是展示。

十八、单独执行
有些工具支持“不纳入工程，只跑一次”的单独执行模式。
适合：
1. 临时对某个 URL 跑一次；
2. 做验证，不想污染当前项目实例；
3. 单独测试某个工具参数。

十九、关于 AI 配置
1. 全局设置里的 AI 配置，是给工具之间协作和 AI 增强功能用的。
2. Codex/Codexx/Claude 各自可以单独设置模型和路线。
3. 工具协作 AI 不等于 CLI 自带模型设置，这两块是分开的。

二十、结论
如果你想知道“现在软件在干什么”，先看项目日志。
如果你想知道“某个工具自己在干什么”，看单工具日志。
如果你想看“给人看的阶段成果”，看 pentest_report.md。
如果你想看“全量机器底稿”，看 risk_summary.md。

????????????????????????
1. fscan ?? POC ??
   - ???????? fscan ????????`-nopoc`?????????????????????????
   - ??????????????????????? deep ?????
2. fscan ??????
   - ??????????`-nobr`????????????????????????????????
   - TscanPlus ?????????????????????????????????????????
3. fscan ?????
   - ??? fscan ???????????????????????????????????????????????????????
4. ???????
   - ??? semantic-recursive-dirscan ??? ffuf ???????????? AI ????????
5. ??????????
   - `0` ????????????????????????????????????????????
6. dirsearch ???
   - ???????? dirsearch ?????????????????semantic ?????????????
7. ????
   - `0` ????????????????????????????????????????????
8. ????
   - balanced???????? fscan ?????? Agent????? fscan POC/????????
   - fast????????????????????
   - deep?????? fscan ????? Agent ???????????????
   - cautious/manual?????????? Agent????????
9. ????
   - ?????? launcher_settings.json??????? project.json?run.json?
   - ????????????????????????????????
   - ????????????? project.json/run.json?activity.log???????????????/????

???????????????????????
1. AssetCommander??????????????
2. fscan/Tscan/??????????? result/tool_data???? asset bus ?????
3. ?????? asset_generation?sources?quiet window?readiness?
4. Agent???????????????Windows Terminal ?????????? PowerShell???????
5. ?????? PID??????????????????????
6. ????????????? fscan???? quiet window?????????????????????????? activity.log ??????

"""


def ensure_help_document(base_dir: Path) -> Path:
    path = base_dir / HELP_FILENAME
    path.write_text(build_help_text(), encoding="utf-8")
    return path
