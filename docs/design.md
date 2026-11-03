# Linux 漏洞挖掘平台：完整实施方案



推荐架构：MCP + Skills + 多 Agent 协作

研究对象：C/C++ 源码



我建议将这个项目命名为 VulnForge，定位为：

> 面向 Linux 基础软件的 AI 辅助漏洞研究平台，通过 MCP 工具提供确定性的代码分析、静态检测、动态测试和证据采集能力，通过 Skills 封装安全研究方法，由 Agent 组织研究过程，最终实现已知漏洞变种挖掘和未知漏洞发现。

目标软件包括：

- OpenSSH
- Nginx
- Apache HTTP Server
- 后续扩展：glibc、systemd、sudo、Linux Kernel 等。

这套平台不是简单地让大模型阅读源码，而是让 AI 具备一套可重复执行、可追踪、可验证的安全研究流程。

我建议采用以下技术原则：

1. MCP 负责工具能力，不负责业务决策。
2. Skills 负责研究方法，不直接替代工具执行。
3. Agent 负责研究任务规划、分析、决策和协作。
4. 所有漏洞结论必须有源码位置、数据流、测试证据或可复现结果支撑。
5. 人工确认负责最终漏洞定性，不能让 LLM 单独宣布发现 0-day。

# 一、整体架构设计

## 1.1 总体架构

用户交互层

CLI / Web UI / API

项目管理 · 研究任务 · 漏洞报告

Agent Orchestration

Research Agent

任务规划、研究协调

Audit Agent

源码安全审计

Fuzz Agent

测试策略和 Fuzz

Triage Agent

崩溃分析、证据复核

Report Agent

漏洞定性材料、报告、回归测试

Agent 使用统一任务状态和证据数据模型

Skills 层

vuln-research · source-audit · attack-surface · cve-analysis · patch-analysis · fuzzing · crash-triage · report

MCP Tool Layer

source_mcp

codeql_mcp

semgrep_mcp

cve_mcp

patch_mcp

fuzz_mcp

crash_mcp

report_mcp

Linux Research Environment

Git · Clang · CodeQL · Semgrep · Joern · AFL++ · libFuzzer · ASan · UBSan · GDB

独立 VM / 容器 · 资源隔离 · 无公网测试目标访问

数据与知识库

PostgreSQL · 文件存储 · Git · CWE/CVE · Patch · Crash Corpus · Research Evidence

这里有一个重要设计决定：

MVP 阶段不需要真正部署五个独立 Agent，也不需要复杂的消息总线。

使用一个主 Agent + 几个按需调用的专业 Skill 即可。MCP Server 独立部署，工具之间保持松耦合。等研究任务复杂度上来之后，再将专业 Agent 拆分。

## 1.2 推荐技术栈

| 模块         | 技术选择                            | 说明          |
| ---------- | ------------------------------- | ----------- |
| Agent 编排   | Python + Google ADK 或 LangGraph | 研究流程控制      |
| MCP Server | Python + FastMCP                | 工具服务        |
| Skill      | Markdown + 脚本                   | 可移植研究方法     |
| 源码解析       | Clang AST                       | C/C++ 结构分析  |
| 静态分析       | CodeQL + Semgrep                | 漏洞检测        |
| 代码属性图      | Joern                           | 深度代码分析，第二阶段 |
| Fuzzing    | AFL++ + libFuzzer               | 动态测试        |
| 动态检测       | ASan + UBSan                    | 内存和未定义行为    |
| 元数据        | PostgreSQL                      | 项目、任务、发现    |
| 证据存储       | 本地文件 / MinIO                    | 日志、Crash、报告 |
| 代码版本       | Git                             | 源码与补丁追踪     |
| 运行环境       | Linux + Docker/Podman + KVM     | 隔离研究环境      |

Agent 框架我倾向于先选 Google ADK 或 LangGraph，但不要把业务逻辑绑定在某个框架上。MCP 是工具接口，Agent 框架可以替换。

# 二、Skills 体系设计

Skills 是整个平台的核心知识资产。

我建议采用两级结构：

- 通用 Skill：定义所有 C/C++ 项目都适用的研究方法。
- 软件专属 Skill：定义 OpenSSH、Nginx、httpd 的代码结构、关键模块和攻击面。

## 2.1 Skill 清单

第一阶段建议实现以下 8 个 Skill。

| Skill             | 优先级 | 输入         | 输出      |
| ----------------- | --- | ---------- | ------- |
| `vuln-research`   | P0  | 研究目标       | 研究计划    |
| `source-audit`    | P0  | 源码目录       | 可疑代码清单  |
| `attack-surface`  | P0  | 项目源码       | 攻击面清单   |
| `cve-analysis`    | P0  | CVE 编号     | 漏洞模式    |
| `patch-analysis`  | P0  | Git Commit | 修复模式    |
| `fuzzing`         | P1  | 目标函数       | Fuzz 任务 |
| `crash-triage`    | P1  | Crash 文件   | 根因分析    |
| `security-report` | P0  | 研究证据       | 漏洞研究报告  |

P0 是 MVP 必须具备的能力，P1 在 MVP 后补充。

## 2.2 通用 Skill 的设计规范

每个 Skill 不应该只是一个 Prompt，而应该包含：

```
source-audit/
├── SKILL.md
├── references/
│   ├── c-memory-safety.md
│   ├── integer-overflow.md
│   ├── input-validation.md
│   └── concurrency.md
├── scripts/
│   └── collect-functions.py
└── examples/
    └── audit-result.json
```

`SKILL.md` 负责工作流程，references 负责知识，scripts 负责可重复执行的辅助操作。

### 示例：vuln-research/SKILL.md

下面给出可以直接作为初始版本使用的 Skill：

```

---
name: vuln-research
description: >
  Linux C/C++ 基础软件漏洞研究。用于历史漏洞变种分析、
  未知漏洞假设生成、源码审计和安全验证。
---

# Vuln Research Skill

## 目标

对授权研究范围内的 Linux C/C++ 软件开展安全研究。

研究目标：
1. 已知 CVE 漏洞变种。
2. 历史修复遗漏。
3. 新的潜在安全缺陷。
4. 可复现的内存安全和逻辑安全问题。

## 输入

- project_name
- source_path
- git_revision
- research_scope
- optional_cve_ids

## 工作流程

### Step 1: 项目理解

- 识别语言、构建系统和依赖。
- 获取版本、分支和 Git Revision。
- 建立源码文件索引。
- 识别关键模块和入口函数。

### Step 2: 历史漏洞研究

- 检索相关 CVE。
- 分析历史漏洞根因。
- 获取修复提交。
- 提取漏洞模式。
- 识别可能存在相同模式的其他代码。

### Step 3: 攻击面分析

识别：
- 网络输入
- 文件输入
- 配置输入
- IPC 输入
- 权限边界
- 信任边界

### Step 4: 源码审计

重点检查：
- Buffer Overflow
- Out-of-bounds Read/Write
- Use-after-free
- Double Free
- Integer Overflow
- Integer Truncation
- Null Pointer Dereference
- Race Condition
- Improper Access Control
- Input Validation

### Step 5: 漏洞假设

每个假设必须包含：
- 代码位置
- 输入来源
- 关键数据流
- 触发前提
- 预期安全影响
- 验证方案

### Step 6: 验证

- 使用静态分析进行辅助验证。
- 使用 Sanitizer 和 Fuzzing 进行动态验证。
- 记录可复现的测试证据。
- 不得将未经验证的假设标记为确认漏洞。

### Step 7: 输出

输出结构化 JSON：
- findings
- evidence
- confidence
- verification_status
- remediation

```

## 2.3 三个软件专属 Skill

### openssh-audit

重点分析：

| 代码模块                 | 研究方向        |
| -------------------- | ----------- |
| SSH Packet           | 报文长度、解析边界   |
| Authentication       | 认证状态转换、权限控制 |
| Key Exchange         | 算法协商、参数处理   |
| Channel              | 通道状态和资源生命周期 |
| SFTP                 | 文件名、路径、文件操作 |
| Privilege Separation | 进程隔离和权限边界   |

### nginx-audit

| 代码模块          | 研究方向               |
| ------------- | ------------------ |
| HTTP Parser   | 请求行、Header、Chunked |
| URI           | URI 规范化和路径处理       |
| Buffer        | 内存边界和生命周期          |
| Configuration | 配置解析和继承            |
| Modules       | 模块间交互              |
| Upstream      | 上游响应和状态管理          |

### httpd-audit

| 代码模块     | 研究方向        |
| -------- | ----------- |
| Core     | 请求处理和资源生命周期 |
| APR      | 内存池和资源管理    |
| HTTP/1.1 | 请求解析        |
| HTTP/2   | 帧解析和状态机     |
| Modules  | 模块接口和信任边界   |
| Proxy    | 代理请求处理      |

这些模块划分应当在正式运行时根据所选源码版本重新验证，不能把模块名称直接当作漏洞存在的证据。

# 三、MCP Server 设计

这是整个系统最值得投入工程精力的地方。

我的建议是：先做 5 个 MCP Server，不要每种分析工具都单独做一个 Server。

## 3.1 MCP Server 划分

| MCP Server            | 包含的工具 | 职责            |
| --------------------- | ----- | ------------- |
| `source-mcp`          | 5 个   | 源码理解          |
| `knowledge-mcp`       | 4 个   | CVE、CWE、Patch |
| `static-analysis-mcp` | 3 个   | 静态分析          |
| `fuzzing-mcp`         | 4 个   | 动态测试          |
| `report-mcp`          | 2 个   | 证据与报告         |

## 3.2 source-mcp

| Tool               | 参数                    | 返回       |
| ------------------ | --------------------- | -------- |
| `project_init`     | project、repo、revision | 项目元数据    |
| `source_index`     | project_id            | 文件和函数索引  |
| `function_search`  | project_id、keyword    | 函数列表     |
| `call_graph`       | project_id、function   | 调用关系     |
| `function_context` | project_id、function   | 函数源码和上下文 |

`function_context` 必须返回文件路径、行号、Git Revision，不能只返回源码文本。

## 3.3 knowledge-mcp

| Tool                    | 参数              | 返回        |
| ----------------------- | --------------- | --------- |
| `cve_lookup`            | cve_id          | CVE 元数据   |
| `cve_history`           | project、version | 历史漏洞列表    |
| `patch_lookup`          | commit_id       | 补丁内容      |
| `patch_pattern_extract` | commit_id       | 漏洞根因和修复模式 |

数据源可以组合：

- NVD
- OSV
- GitHub Security Advisories
- 软件官方安全公告
- 项目 Git 仓库
- 发行版安全公告和补丁记录

对于发行版场景，要特别注意上游版本号和发行版回移补丁之间的区别。

## 3.4 static-analysis-mcp

| Tool           | 参数                    | 返回    |
| -------------- | --------------------- | ----- |
| `codeql_scan`  | project_id、query_pack | SARIF |
| `semgrep_scan` | project_id、ruleset    | JSON  |
| `codeql_query` | project_id、query_file | 查询结果  |

CodeQL 结果必须保留 query ID、source/sink、代码位置和路径信息；Semgrep 结果保留规则 ID、严重性和源码位置。

## 3.5 fuzzing-mcp

| Tool                 | 参数                     | 返回            |
| -------------------- | ---------------------- | ------------- |
| `fuzz_target_create` | project_id、target_spec | Harness 和构建配置 |
| `fuzz_start`         | target_id、duration     | Job ID        |
| `fuzz_status`        | job_id                 | 覆盖率和运行状态      |
| `fuzz_result`        | job_id                 | Crash 和统计数据   |

Fuzzing 工具必须实施资源限制，不能让 Agent 自由指定宿主机命令或任意执行参数。

## 3.6 report-mcp

| Tool                | 参数                     | 返回    |
| ------------------- | ---------------------- | ----- |
| `evidence_register` | finding_id、evidence    | 证据 ID |
| `report_generate`   | project_id、finding_ids | 报告路径  |

报告需要区分：

- 已确认漏洞。
- 可疑漏洞。
- 仅有崩溃、尚未证明安全影响的问题。
- 已知 CVE 的变种。
- 已知 CVE 的重复发现。

## 3.7 统一 MCP 数据结构

这是我认为必须优先设计的部分。

所有 MCP 工具都应该使用统一的项目、任务和证据标识。

例如：

```
{
  "project_id": "nginx-001",
  "task_id": "task-20261103-001",
  "finding_id": "finding-001",
  "project": {
    "name": "nginx",
    "version": "1.x",
    "git_revision": "abcdef"
  },
  "finding": {
    "category": "memory-safety",
    "cwe": "CWE-125",
    "severity": "unknown",
    "status": "candidate"
  },
  "location": {
    "file": "src/http/ngx_http_parse.c",
    "function": "example",
    "line_start": 100,
    "line_end": 120
  },
  "evidence": [],
  "verification": {
    "status": "not_verified",
    "reproducible": false
  }
}
```

注意：`severity` 初始值应该允许为 `unknown`，不能在没有攻击条件和影响分析时直接让模型给出 Critical。

# 四、Agent 协作机制

我建议使用一个主 Agent 和四个专业 Agent，Report Agent 作为最终处理阶段。

## 4.1 Agent 职责

| Agent           | 角色      | 核心任务             |
| --------------- | ------- | ---------------- |
| Research Agent  | 主 Agent | 任务规划、工作流编排       |
| Knowledge Agent | 漏洞知识研究员 | CVE、CWE、历史 Patch |
| Audit Agent     | 源码审计员   | 攻击面、数据流、危险代码     |
| Fuzz Agent      | 动态测试工程师 | Harness、Fuzz、覆盖率 |
| Triage Agent    | 漏洞分析师   | Crash 去重、根因和安全影响 |
| Report Agent    | 报告工程师   | 证据整理、报告生成        |

Research Agent 负责分配任务，但不能自行改变测试范围。

## 4.2 Agent 协作流程

以 Nginx 的一次漏洞研究为例：

\#chatgpt-mermaid-\_r_tt\_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,Segoe UI,Helvetica,Apple Color Emoji,Arial,sans-serif,Segoe UI Emoji,Segoe UI Symbol;font-size:16px;fill:rgb(13, 13, 13);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-\_r_tt\_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_tt\_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_tt\_ .error-icon{fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_tt\_ .error-text{fill:rgb(13, 13, 13);stroke:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_tt\_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-\_r_tt\_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-\_r_tt\_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-\_r_tt\_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-\_r_tt\_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-\_r_tt\_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-\_r_tt\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_tt\_ .marker.cross{stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_tt\_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,Segoe UI,Helvetica,Apple Color Emoji,Arial,sans-serif,Segoe UI Emoji,Segoe UI Symbol;font-size:16px;}#chatgpt-mermaid-\_r_tt\_ p{margin:0;}#chatgpt-mermaid-\_r_tt\_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,Segoe UI,Helvetica,Apple Color Emoji,Arial,sans-serif,Segoe UI Emoji,Segoe UI Symbol;color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_tt\_ .cluster-label text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_tt\_ .cluster-label span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_tt\_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-\_r_tt\_ .label text,#chatgpt-mermaid-\_r_tt\_ span{fill:rgb(13, 13, 13);color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_tt\_ .node rect,#chatgpt-mermaid-\_r_tt\_ .node circle,#chatgpt-mermaid-\_r_tt\_ .node ellipse,#chatgpt-mermaid-\_r_tt\_ .node polygon,#chatgpt-mermaid-\_r_tt\_ .node path{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-\_r_tt\_ .rough-node .label text,#chatgpt-mermaid-\_r_tt\_ .node .label text,#chatgpt-mermaid-\_r_tt\_ .image-shape .label,#chatgpt-mermaid-\_r_tt\_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-\_r_tt\_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-\_r_tt\_ .rough-node .label,#chatgpt-mermaid-\_r_tt\_ .node .label,#chatgpt-mermaid-\_r_tt\_ .image-shape .label,#chatgpt-mermaid-\_r_tt\_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-\_r_tt\_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-\_r_tt\_ .root .anchor path{fill:rgb(143, 143, 143)!important;stroke-width:0;stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_tt\_ .arrowheadPath{fill:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_tt\_ .edgePath .path{stroke:rgb(143, 143, 143);stroke-width:1px;}#chatgpt-mermaid-\_r_tt\_ .flowchart-link{stroke:rgb(143, 143, 143);fill:none;}#chatgpt-mermaid-\_r_tt\_ .edgeLabel{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_tt\_ .edgeLabel p{background-color:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_tt\_ .edgeLabel rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_tt\_ .labelBkg{background-color:rgba(252, 252, 252, 0.5);}#chatgpt-mermaid-\_r_tt\_ .cluster rect{fill:rgb(243, 243, 243);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_tt\_ .cluster text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_tt\_ .cluster span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_tt\_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,Segoe UI,Helvetica,Apple Color Emoji,Arial,sans-serif,Segoe UI Emoji,Segoe UI Symbol;font-size:12px;background:rgb(243, 243, 243);border:1px solid rgba(0, 0, 0, 0.1);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-\_r_tt\_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_tt\_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-\_r_tt\_ .icon-shape,#chatgpt-mermaid-\_r_tt\_ .image-shape{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_tt\_ .icon-shape p,#chatgpt-mermaid-\_r_tt\_ .image-shape p{background-color:rgb(252, 252, 252);padding:2px;}#chatgpt-mermaid-\_r_tt\_ .icon-shape .label rect,#chatgpt-mermaid-\_r_tt\_ .image-shape .label rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_tt\_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-\_r_tt\_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-\_r_tt\_ .node .neo-node{stroke:rgb(83, 154, 248);}#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].node rect,#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].cluster rect,#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-\_r_tt\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-\_r_tt\_-gradient);stroke-width:1px;}#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].node .neo-line path{stroke:rgb(83, 154, 248);filter:none;}#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-\_r_tt\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-\_r_tt\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_tt\_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-\_r_tt\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_tt\_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_tt\_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_tt\_ .node tspan[font-weight="normal"],#chatgpt-mermaid-\_r_tt\_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-\_r_tt\_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-width:1px;}#chatgpt-mermaid-\_r_tt\_ .node rect,#chatgpt-mermaid-\_r_tt\_ .node circle,#chatgpt-mermaid-\_r_tt\_ .node ellipse,#chatgpt-mermaid-\_r_tt\_ .node polygon,#chatgpt-mermaid-\_r_tt\_ .node path{fill:rgb(229, 243, 255);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_tt\_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-\_r_tt\_ .mermaid-decision .label-container{fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-dasharray:2px,2px;}#chatgpt-mermaid-\_r_tt\_ .edgePaths .flowchart-link{stroke:rgb(143, 143, 143);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-\_r_tt\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_tt\_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,Segoe UI,Helvetica,Apple Color Emoji,Arial,sans-serif,Segoe UI Emoji,Segoe UI Symbol;}用户：研究 NginxResearch AgentKnowledge AgentAudit Agent历史 CVE / Patch 模式攻击面 / 函数 / 数据流研究候选点Research Agent 优先级排序Audit Agent 深入审计是否有可信漏洞假设记录未发现并结束该分支Fuzz AgentCrash / SanitizerTriage Agent证据是否充分Report Agent人工安全复核漏洞研究报告否是否是

### 关键机制：候选点优先级

不能让 Agent 把整个项目所有函数都分析一遍，这会浪费大量 Token 和计算资源。

建议给每个函数建立一个风险评分：

\\[ Score = 0.25I + 0.20H + 0.20C + 0.20D + 0.15R \\]

其中各项归一化到 0～100：

- I：外部输入可达性。
- H：历史漏洞关联程度。
- C：代码复杂度。
- D：危险操作密度。
- R：权限边界和资源管理风险。

例如：

| 函数     | 输入可达 | 历史关联 | 复杂度 | 危险操作 | 综合分  |
| ------ | ---- | ---- | --- | ---- | ---- |
| func_A | 90   | 80   | 70  | 85   | 81.5 |
| func_B | 30   | 20   | 80  | 60   | 46.0 |
| func_C | 70   | 90   | 90  | 90   | 85.0 |

这个评分只用于确定研究顺序，不是漏洞概率或严重程度。

## 4.3 研究状态机

建议所有研究任务采用统一状态机：

```
CREATED
   |
   v
PROJECT_ANALYSIS
   |
   v
ATTACK_SURFACE_ANALYSIS
   |
   v
STATIC_ANALYSIS
   |
   v
CANDIDATE_GENERATION
   |
   v
MANUAL_REVIEW
   |
   +------> REJECTED
   |
   v
DYNAMIC_VALIDATION
   |
   +------> UNCONFIRMED
   |
   v
CONFIRMED
   |
   v
REPORT_GENERATED
   |
   v
HUMAN_REVIEWED
```

其中 `CONFIRMED` 不能由单一 Agent 的自然语言判断触发，必须满足预定义的证据条件。

## 4.4 两种研究模式

平台需要同时支持你选择的 both 目标。

模式 A：已知漏洞变种挖掘

建议优先实现

1. 输入 CVE 或历史安全 Patch。
2. 提取根因和修复代码差异。
3. 总结漏洞模式及修复约束。
4. 搜索项目中相似的函数和代码结构。
5. 比较修复前后的安全约束是否完整。
6. 生成候选问题并进行验证。

模式 B：未知漏洞挖掘

1. 识别外部输入入口。
2. 追踪输入到敏感操作的数据流。
3. 识别边界检查、状态检查和资源管理问题。
4. 生成漏洞假设。
5. 使用静态分析和 Fuzzing 进行验证。

我建议先把模式 A 做好。原因是历史漏洞和修复 Patch 能给 Agent 提供高质量的研究依据，比完全开放式的源码分析更容易产生有价值的结果。

# 五、Linux 研究环境搭建

## 5.1 硬件建议

| 配置     | MVP           | 推荐研发环境                   |
| ------ | ------------- | ------------------------ |
| CPU    | 8 核           | 16～32 核                  |
| 内存     | 16 GB         | 32～64 GB                 |
| 磁盘     | 100 GB        | 500 GB SSD               |
| OS     | Ubuntu 24.04  | Ubuntu 24.04 / openEuler |
| Python | 3.11+         | 3.11+                    |
| 容器     | Docker/Podman | Docker/Podman + KVM      |

LLM 可以使用外部 API，也可以使用本地模型。MVP 不需要 GPU。

注意：Fuzzing 的 CPU 和内存资源应与 Agent 服务分开限制。长期 Fuzzing 最好使用独立虚拟机，而不是直接在宿主机执行。

## 5.2 安装基础依赖

Ubuntu 示例：

```
sudo apt update

sudo apt install -y \
    build-essential \
    clang \
    llvm \
    cmake \
    ninja-build \
    git \
    gdb \
    python3 \
    python3-venv \
    python3-dev \
    pkg-config \
    libssl-dev \
    libpcre2-dev \
    zlib1g-dev \
    ripgrep \
    jq \
    docker.io
```

Python 工具环境：

```
mkdir -p /opt/vulnforge
cd /opt/vulnforge

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install "mcp>=1.28,<2" semgrep
```

这里的 MVP 示例采用 MCP Python SDK 1.x 的 FastMCP API，因此需要锁定版本；官方 SDK 当前已有 v2 稳定版本，后续升级时应按照迁移指南调整接口。

[image](https://www.google.com/s2/favicons?domain=https://py.sdk.modelcontextprotocol.io\&sz=32)

MCP Python SDK+1



## 5.3 安装 CodeQL

CodeQL CLI 单独部署，建议固定经过验证的版本：

[CodeQL CLI 官方二进制仓库](https://github.com/github/codeql-cli-binaries?utm_source=chatgpt.com)

安装后：

```
codeql version
```

建立 C/C++ 数据库：

```
codeql database create \
  /opt/vulnforge/db/nginx \
  --language=cpp \
  --source-root=/opt/vulnforge/source/nginx \
  --command="make -j$(nproc)"
```

实际项目应先按官方构建方式配置依赖和构建选项，确保 CodeQL 能捕获完整编译过程。

## 5.4 安装 AFL++

```
sudo apt install -y afl++
afl-clang-fast --version
```

或者从官方仓库构建：

[AFL++ 官方仓库](https://github.com/AFLplusplus/AFLplusplus?utm_source=chatgpt.com)

Fuzzing 建议支持两类模式：

- Coverage-guided Fuzzing：使用 AFL++。
- In-process Fuzzing：使用 libFuzzer。

对于后续大规模持续测试，可以借鉴 OSS-Fuzz 的项目配置、语料库管理、Sanitizer 和任务调度机制。

[image](https://www.google.com/s2/favicons?domain=https://github.com\&sz=32)

GitHub+1



## 5.5 研究环境目录

```
/opt/vulnforge/
├── .venv/
├── config/
│   ├── projects.yaml
│   └── policy.yaml
├── mcp-servers/
│   ├── source/
│   ├── knowledge/
│   ├── static/
│   ├── fuzzing/
│   └── report/
├── skills/
│   ├── vuln-research/
│   ├── source-audit/
│   ├── attack-surface/
│   ├── cve-analysis/
│   ├── patch-analysis/
│   ├── fuzzing/
│   └── crash-triage/
├── source/
│   ├── nginx/
│   ├── openssh/
│   └── httpd/
├── database/
├── findings/
├── fuzzing/
└── reports/
```

建议将源码目录设为只读快照，工具只在工作副本中运行分析。

# 六、第一个可运行 MVP：Nginx 源码安全审计

这是整个方案最重要的落地部分。

不要第一天就实现全部 Agent 和 MCP Server。

我建议第一个 MVP 只完成一个闭环：

MVP 验收目标

用户输入：

```
请分析 Nginx 源码中的潜在内存安全问题，
重点关注 HTTP 请求解析、长度计算和内存拷贝。
```

系统能够：

1. 读取指定版本的 Nginx 源码。
2. 提取函数和关键代码。
3. 执行 Semgrep 安全规则。
4. 分析潜在危险代码。
5. 生成带源码位置的候选问题。
6. 输出 Markdown 研究报告。

第一阶段不自动生成攻击性 PoC，不对公网运行测试，也不将静态扫描结果直接标记为已确认漏洞。

## 6.1 MVP 架构

```
用户
 |
 v
Research Agent
 |
 +-- vuln-research Skill
 |
 +-- source-audit Skill
 |
 v
source-mcp
 |
 +-- project_init
 +-- list_source_files
 +-- search_source
 +-- read_source
 |
 v
static-analysis-mcp
 |
 +-- semgrep_scan
 |
 v
Research Agent
 |
 v
candidate_findings.json
 |
 v
security-report Skill
 |
 v
report.md
```

## 6.2 初始化项目

```
cd /opt/vulnforge

mkdir -p source findings reports
git clone https://github.com/nginx/nginx.git source/nginx

cd source/nginx

git checkout release-1.28.0

git rev-parse HEAD
```

这里固定一个版本只是为了保证研究可重复，不代表这是最新版本或存在已知漏洞。

## 6.3 编写第一个 MCP Server

创建：

```
mcp-servers/source/server.py
```

下面这段代码实现一个真正可以运行的只读源码 MCP Server。

```
import osimport refrom pathlib import Pathfrom mcp.server.fastmcp import FastMCPmcp = FastMCP("vulnforge-source")ROOT = Path(    os.getenv("VULNFORGE_SOURCE_ROOT", "/opt/vulnforge/source")).resolve()ALLOWED_EXTENSIONS = {    ".c", ".h", ".cc", ".cpp", ".hpp"}MAX_READ_LINES = 300MAX_SEARCH_RESULTS = 100def resolve_project(project: str) -> Path:    """只允许访问 ROOT 下已登记的项目目录。"""    if not re.fullmatch(r"[a-zA-Z0-9_-]+", project):        raise ValueError("Invalid project name")    path = (ROOT / project).resolve()    if not path.is_relative_to(ROOT):        raise ValueError("Project path outside root")    if not path.is_dir():        raise ValueError("Project does not exist")    return path
```

说明：这是 MVP 级源码浏览器，不是完整的源码解析器。正式版本还需要 Git Revision 校验、忽略目录规则、文件大小限制、并发控制和更严格的符号链接隔离。

## 6.4 启动 MCP Server

```
export VULNFORGE_SOURCE_ROOT=/opt/vulnforge/source

source /opt/vulnforge/.venv/bin/activate

python /opt/vulnforge/mcp-servers/source/server.py
```

采用 stdio 传输时，Server 会等待 MCP Host 启动并与它通信。不要向 stdout 输出普通调试日志，以免破坏协议通信。

## 6.5 添加 Semgrep 规则

创建：

```
config/rules/c-memory.yml
```

```

rules:
  - id: suspicious-unbounded-copy
    languages: [c]
    severity: WARNING
    message: >
      Potentially unsafe memory copy. Review source length,
      destination capacity and boundary checks.
    patterns:
      - pattern-either:
          - pattern: strcpy($DST, $SRC)
          - pattern: strcat($DST, $SRC)

  - id: suspicious-format-string
    languages: [c]
    severity: WARNING
    message: >
      Review externally controlled format strings.
    pattern: printf($FMT, ...)

  - id: suspicious-memory-allocation
    languages: [c]
    severity: WARNING
    message: >
      Review allocation size calculation and integer overflow.
    pattern: malloc($SIZE * $COUNT)

```

这些规则只是初筛规则，会有误报和漏报。比如 `printf` 的格式字符串本身未必存在问题，乘法分配也需要结合类型、取值范围和检查逻辑分析。

执行：

```
semgrep \
  --config config/rules/c-memory.yml \
  --json \
  source/nginx \
  > findings/semgrep.json
```

之后由 Audit Agent 分析结果，结合上下文确认是否存在真实风险。

## 6.6 Agent 的第一个研究 Prompt

```

你是 VulnForge 的 Linux C/C++ 安全研究 Agent。

目标：
分析已登记的 Nginx 源码项目，寻找潜在的内存安全问题。

研究重点：
1. HTTP 请求解析。
2. 输入长度校验。
3. 内存分配与长度计算。
4. 内存拷贝和字符串处理。
5. 缓冲区生命周期。

执行步骤：

1. 调用 list_source_files 了解源码结构。
2. 调用 search_source 定位危险函数。
3. 使用 read_source 读取完整上下文。
4. 结合 Semgrep 扫描结果进行审计。
5. 分析外部输入是否可达危险操作。
6. 检查长度约束和边界检查。
7. 为有证据的候选问题建立 Finding。

输出必须包含：

- Finding ID
- CWE（如适用）
- 文件路径
- 行号
- 函数名称
- 可疑代码
- 输入来源
- 关键数据流
- 触发条件
- 潜在安全影响
- 尚缺少的验证证据
- 修复建议

约束：

不得仅凭危险函数调用认定漏洞。
不得将静态扫描结果直接认定为已确认漏洞。
区分事实、推断和待验证假设。
所有结论必须能够追溯到源码和工具证据。
仅在授权的本地研究环境内进行分析。

```

## 6.7 MVP 最终输出

建议统一输出：

```
reports/
└── nginx/
    └── research-20261103/
        ├── summary.md
        ├── findings.json
        ├── static-analysis.json
        ├── source-evidence/
        └── execution-log.json
```

报告至少包含：

| 章节      | 内容              |
| ------- | --------------- |
| 1. 研究概要 | 版本、Commit、范围    |
| 2. 分析方法 | Skills、MCP、分析工具 |
| 3. 攻击面  | 外部输入和信任边界       |
| 4. 静态分析 | 规则和分析结果         |
| 5. 候选漏洞 | CWE、代码、数据流      |
| 6. 验证情况 | 测试证据和限制         |
| 7. 修复建议 | 代码级建议           |
| 8. 附录   | 日志、源码位置、工具版本    |

MVP 验收不以发现漏洞数量为目标，而以完整性和可复现性为目标：同一个 Commit、相同规则和配置，应该得到可以比较的分析结果。

# 七、进一步完善：MCP 工具接口规范

MVP 验证通过之后，不要立即增加大量工具。建议先统一工具契约，避免以后不同 Agent 使用不同的数据格式。

例如：

### `source.search`

```
{
  "project_id": "nginx-001",
  "query": "memcpy",
  "file_patterns": ["*.c", "*.h"],
  "limit": 50
}
```

### `static.codeql_scan`

```
{
  "project_id": "nginx-001",
  "revision": "abcdef",
  "query_pack": "c-cpp-security",
  "timeout_seconds": 1800
}
```

### `knowledge.patch_analyze`

```
{
  "project_id": "nginx-001",
  "commit_id": "abcdef",
  "analysis_mode": "security_patch"
}
```

### `fuzzing.start`

```
{
  "project_id": "nginx-001",
  "target_id": "http-parser",
  "engine": "libfuzzer",
  "sanitizers": ["address", "undefined"],
  "duration_seconds": 3600,
  "max_memory_mb": 2048
}
```

这些是建议的逻辑接口，不是已经实现的 MCP Schema。

每个 MCP 工具统一返回：

```
{
  "success": true,
  "task_id": "task-001",
  "data": {},
  "evidence_ids": [],
  "error": null
}
```

工具应支持任务取消、超时、进度查询和结果分页。长时间 Fuzzing 必须采用异步 Job 模式，不要让一次 MCP 调用一直阻塞。

# 八、项目实施路线图

我建议分四个阶段，约 4 周完成第一版可用平台。

## VulnForge 研发计划

1. 第一周：源码分析基础设施

   P0
   - Linux 环境部署
   - Nginx 源码管理
   - source-mcp
   - Semgrep 集成
   - source-audit Skill
   交付：可以通过 MCP 查询源码、定位危险代码并输出分析结果。
2. 第二周：历史漏洞变种分析
   - knowledge-mcp
   - CVE 和 Patch 分析
   - cve-analysis Skill
   - patch-analysis Skill
   - CodeQL 集成
   交付：输入历史 CVE，自动分析补丁并寻找相似代码。
3. 第三周：Fuzzing 自动化
   - fuzzing-mcp
   - libFuzzer / AFL++
   - Sanitizer
   - crash-triage Skill
   - Crash 归档和去重
   交付：可以从候选代码路径进入动态测试，保存可复现的崩溃样本。
4. 第四周：Agent 编排与报告
   - Research Agent
   - Audit Agent
   - Triage Agent
   - Report Agent
   - 完整研究工作流
   - 人工审核机制
   交付：输入研究任务，生成完整的漏洞研究报告。

## 8.1 MVP 验收标准

| 验收项    | 通过标准                  |
| ------ | --------------------- |
| 源码管理   | 能够固定版本和 Commit        |
| MCP    | 至少 3 个源码工具可正常调用       |
| Skill  | 至少 3 个 Skill 可以指导研究流程 |
| 静态分析   | 能够生成 Semgrep JSON 结果  |
| 证据追踪   | 每个候选问题关联源码位置          |
| CVE 研究 | 能够分析历史漏洞及其 Patch      |
| 报告     | 能够生成 Markdown 报告      |
| 可重复性   | 相同输入可以重现研究过程          |
| 安全隔离   | 分析任务不能越权访问宿主机         |

# 九、几个特别重要的工程设计

这部分决定平台以后能否从一个 Demo 变成真正可用的研究工具。

### 9.1 不要让 Agent 直接执行 Shell

建议：

```
Agent
  |
  v
MCP Tool
  |
  v
Task Executor
  |
  v
Sandbox
  |
  v
Result
```

例如 Agent 请求执行 CodeQL，MCP Server 应该根据固定的工具配置构造命令，而不是接受模型传入任意 Shell 字符串。

尤其是：

- 不允许任意删除源码。
- 不允许访问宿主机敏感目录。
- 不允许任意执行网络请求。
- 不允许修改研究范围之外的文件。
- Fuzzing 默认禁止公网目标访问。
- 所有长时间任务都必须有资源限制。

### 9.2 漏洞证据必须分级

我建议使用以下等级：

| 等级 | 含义            |
| -- | ------------- |
| E0 | LLM 提出的研究假设   |
| E1 | 找到具体可疑源码位置    |
| E2 | 静态分析证明存在可疑数据流 |
| E3 | 动态测试观察到异常行为   |
| E4 | 复现了明确的安全影响    |
| E5 | 人工复核并形成完整漏洞报告 |

注意，E3 的 Crash 不等于安全漏洞。E4 也需要结合攻击前提和影响判断，E5 才是经过研究审核的结论。

### 9.3 已知漏洞变种分析要建立 Patch 知识库

这是我认为平台最有价值的能力之一。

例如：

```
历史 CVE
   |
   v
修复 Commit
   |
   v
Patch Diff
   |
   v
根因分析
   |
   v
漏洞模式提取
   |
   v
寻找相似代码
   |
   v
检查安全约束
   |
   v
生成候选 Finding
```

例如，历史 Patch 修复的是某个长度计算缺少整数溢出检查。

Agent 不应该只是搜索相同的函数名，而应该理解：

- 原始输入来自哪里？
- 长度计算是否受输入控制？
- 是否存在溢出？
- 分配长度和实际拷贝长度是否一致？
- 是否有其他路径绕过了检查？

这样才能从简单的代码搜索进化为漏洞模式研究。

### 9.4 发行版场景要加入补丁映射

考虑到 Linux 基础软件研究，建议数据模型支持：

```
Upstream Version
       |
       v
Distribution Package
       |
       v
Vendor Patch
       |
       v
Build Configuration
       |
       v
Binary Package
```

同一个上游 CVE，可能在发行版中通过回移补丁修复，而不改变上游版本号。

后续可以将你之前研究的 CVE 修复验证能力直接接入 VulnForge：

- 上游是否修复。
- 发行版是否回移。
- 补丁是否实际应用。
- 当前构建产物是否包含修复。
- 是否存在其他未覆盖的代码路径。

这能让平台同时具备漏洞挖掘和发行版安全验证能力。

# 十、参考项目与官方资料

建议将以下项目作为 VulnForge 的技术基础，而不是从零实现所有分析能力。

| 项目             | 在 VulnForge 中的用途 | 官方地址                                                                                |
| -------------- | ---------------- | ----------------------------------------------------------------------------------- |
| MCP Python SDK | MCP Server       | [GitHub](https://github.com/modelcontextprotocol/python-sdk?utm_source=chatgpt.com) |
| CodeQL         | 源码数据流分析          | [官网](https://codeql.github.com/?utm_source=chatgpt.com)                             |
| Semgrep        | 自定义规则扫描          | [官网](https://semgrep.dev/?utm_source=chatgpt.com)                                   |
| AFL++          | 覆盖率引导 Fuzzing    | [GitHub](https://github.com/AFLplusplus/AFLplusplus?utm_source=chatgpt.com)         |
| OSS-Fuzz       | 持续 Fuzzing 体系    | [GitHub](https://github.com/google/oss-fuzz?utm_source=chatgpt.com)                 |
| Joern          | C/C++ 代码属性图      | [GitHub](https://github.com/joernio/joern?utm_source=chatgpt.com)                   |

另外，MCP 的 Tool、Resource、Prompt 三种能力应当分别使用：Tool 执行动作，Resource 提供项目和研究证据，Prompt 提供可复用研究模板。

[image](https://www.google.com/s2/favicons?domain=https://py.sdk.modelcontextprotocol.io\&sz=32)

MCP Python SDK+1

&#x20;这样设计可以避免把所有东西都堆到 Tool 接口中。



# 十一、最终建议：先做一个能发现真实问题的最小闭环

我会把整个项目拆成三个产品阶段：

V1：AI Source Auditor

先做

源码审计、CVE 历史分析、Patch 分析、候选问题报告。

目标：提高人工代码审计效率。

V2：AI Vulnerability Hunter

自动构造 Fuzz Harness、动态测试、Crash 分析、漏洞变种发现。

目标：让 AI 从代码分析走向漏洞验证。

V3：Linux Security Research Platform

多软件、多版本、多架构、多发行版研究；自动回归验证；长期漏洞知识库。

目标：形成持续的 Linux 基础软件安全研究能力。

我的一个核心判断：VulnForge 最值得投入的不是 Agent 数量，而是 Patch 知识库 + 代码数据流分析 + 自动验证闭环。

这三个部分构成平台真正的技术壁垒。单纯使用 LLM 阅读源码，很容易得到大量看起来合理、实际上无法复现的漏洞猜测。

## 建议下一步直接进入代码实现

我建议第一批代码只创建以下内容：

```
vulnforge/
├── pyproject.toml
├── config/
│   └── projects.yaml
├── mcp_servers/
│   ├── source_server.py
│   └── static_server.py
├── skills/
│   ├── vuln-research/SKILL.md
│   ├── source-audit/SKILL.md
│   └── patch-analysis/SKILL.md
├── rules/
│   └── c-memory.yml
├── schemas/
│   └── finding.schema.json
├── tests/
└── README.md
```

第一轮先实现两个 MCP Server、三个 Skill 和一个 Nginx 审计工作流。等它能够稳定完成一次从源码定位到证据报告的研究任务，再扩展 CVE 变种分析和 Fuzzing。

这样能最大限度降低项目复杂度，也能尽早验证这套技术路线是否真的能帮助你发现代码中的安全问题。
