# secretsweep

**在笔记或仓库公开之前，找出并脱敏里面的密钥、内网地址和个人信息。**

[![CI](https://github.com/zcf-AI2026/secretsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/zcf-AI2026/secretsweep/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/secretsweep.svg)](https://pypi.org/project/secretsweep/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

辛辛苦苦整理的一批笔记、或者一个准备开源的项目，里面可能躺着生产服务器 IP、一个忘了的
API Key、一个手机号、一条本地绝对路径。`secretsweep` 负责把它们找出来，替换成可读的
占位符（`⟨PRIVATE_IP⟩`），同时把**真实值记在一份本地私密的映射表**里 —— 以后需要时
随时还原。

零依赖，Python 3.11+，一次性命令行工具，不常驻、不联网。

---

## 和现成的密钥扫描器有什么不同？

扫描器告诉你"第 42 行有问题"。如果你的代码不能改，这是对的答案；但如果你要**发布**
一份文档，你需要的是：文字还得读得通，而原始值得留在一个私密的地方。

| | 扫描器（gitleaks、detect-secrets…） | `secretsweep` |
|---|---|---|
| 目的 | 拦住提交 | **产出一份能公开的副本** |
| 输出 | 问题列表 | 问题列表 **+ 脱敏后的正文** |
| 可逆 | 否 | **是（凭本地映射表）** |
| 占位符 | 无 | 有语义：`⟨PRIVATE_IP⟩`、`⟨DB_URL⟩` |
| 适用 | 代码 | 代码 **+ 散文 / 笔记 / 文档** |

## 安装

```bash
pipx install secretsweep      # 推荐：独立的 CLI 环境
# 或者
pip install secretsweep
```

## 四个命令

```bash
secretsweep scan  ~/notes     # 只看不动：会改什么？
secretsweep apply ~/notes     # 就地替换，并写出 secretsweep.map.json
secretsweep restore ~/notes   # 用映射表把原值放回去
secretsweep check ~/notes     # 有命中就以退出码 1 结束（给 CI / pre-commit 用）
```

真实输出：

```text
$ secretsweep scan examples/
RULE          LOCATION                 VALUE
------------  -----------------------  --------
ipv4_public   examples/demo-note.md:3  203***42
ipv4_private  examples/demo-note.md:3  10.***40
phone_cn      examples/demo-note.md:4  138***00
email         examples/demo-note.md:4  ops***om
github_token  examples/demo-note.md:5  ghp***00
db_url        examples/demo-note.md:6  pos***pp
```

报告里的值都是**打码**的（`203***42`），所以扫描结果可以放心贴给别人看。需要机读
就加 `-f json`。

## 内置规则

私钥块、GitHub Token、`sk-` 密钥、AWS AK、JWT、数据库连接串、私有/公网 IPv4、
中国大陆手机号、邮箱、`/Users/<名字>` 与 `/home/<名字>` 路径。
完整列表：`secretsweep rules`。

> 文档示例里用的 IP 都是 RFC 5737 保留段（`203.0.113.x`、`198.51.100.x`），
> 不会指向任何真实主机。

## 配置（`secretsweep.toml`）

```toml
[settings]
allow = ["example.com", "192.0.2.10"]   # 精确匹配，直接忽略
placeholder_format = "⟨{name}⟩"          # 也可以换成 "<<{name}>>"

[[rule]]                                 # 复用内置 id = 覆盖它
id = "ipv4_public"
pattern = '''\b(?:\d{1,3}\.){3}\d{1,3}\b'''
placeholder = "IP"

[[rule]]                                 # 新 id = 追加
id = "internal_host"
pattern = '''\b[a-z0-9-]+\.corp\.example\b'''
placeholder = "INTERNAL_HOST"
```

`secretsweep init` 会生成一份带注释的模板。

## 作为 pre-commit 钩子

```yaml
repos:
  - repo: https://github.com/zcf-AI2026/secretsweep
    rev: v0.1.0
    hooks:
      - id: secretsweep
```

命中即**阻止提交**，但不改任何文件。

## 工作方式（四点要知道）

1. 只处理已知扩展名的文本文件，跳过二进制、`.git`、`node_modules`（可用
   `--ext` / `--exclude` 调整）。
2. 多条规则命中同一段时，取"起点最早、长度最长"的那条 —— 所以一条数据库连接串会被
   整体替换，而不是被拆得七零八落。
3. 占位符**按正文顺序**分配：第一个值拿到 `⟨PRIVATE_IP⟩`，下一个是
   `⟨PRIVATE_IP_2⟩`；同一个值在所有文件里始终是同一个占位符。
4. 值 ↔ 占位符的对应关系写进 `secretsweep.map.json`（权限 600）。**这份文件等同于
   原始数据，务必不要提交**。

## 安全提示

- 映射表和数据本身一样敏感：加进 `.gitignore`（仓库自带的已经加了），用完可以删。
- 先 `scan` 或 `apply --dry-run`，看清影响面再动手。
- 它是正则驱动的：它不可能知道"项目猎鹰"是你的内部代号 —— 这类业务词请自己加规则。
- 动手前先 commit，`git diff` 就是你的后悔药。

## 已知局限

目前只做正则匹配，没有熵值/模型检测；不做跨行上下文判断。
路线图：`--diff` 只扫暂存区、YAML 规则包、`git filter-repo` 历史清理助手、IPv6、
HTML 报告。

## 许可

MIT，见 [LICENSE](LICENSE)。
