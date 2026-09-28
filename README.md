# dtsd — 本地 DNS 隧道流量检测与告警服务

一个不依赖外部服务、不需要真实凭据的**本地** DNS 隧道检测引擎。输入是带时间戳的
DNS 查询事件流（来自本地回环或内存通道），事件允许乱序、迟到到达。引擎基于
多维特征 + 可演进基线 + 滑动窗口疑似度累积来识别隧道行为，并通过去重/冷却、
白名单/豁免、有界内存和崩溃恢复来控制误报、告警风暴与长期运行风险。

## 快速开始

```bash
go run ./cmd/dtsd        # 内存通道演示：正常/心跳/白名单/隧道混合流量
go test ./...            # 全部单元与集成测试
go test -race ./...      # 含竞态检测
```

演示使用一个内存通道产生事件（无网络监听、无凭据），打印有效告警并把状态
原子快照到临时目录。

## 包结构

| 包 | 职责 |
|---|---|
| `pkg/model` | 事件、响应、告警、严重度、告警生命周期更新等核心类型 |
| `pkg/features` | 名称结构特征（最长标签、长度、香农熵、数字比例）、Welford 流式统计、EWMA 速率/间隔跟踪 |
| `pkg/baseline` | 按 `(客户端, 系列根域)` 隔离的可演进基线，指数衰减实现基线漂移，LRU 有界 |
| `pkg/window` | 固定宽度桶的滑动窗口，确定性推进，乱序/迟到容忍，疑似度累积 |
| `pkg/alert` | 告警去重、冷却、严重度升级、冷却到期 reopen，可解释的重复计数 |
| `pkg/persist` | 版本化快照，临时文件 + fsync + 原子 rename 的崩溃安全持久化 |
| `pkg/config` | 配置、白名单/豁免规则、**不可变**配置快照与代次（generation） |
| `pkg/detector` | 并发分片摄入、打分编排、水位推进、热更新、快照/恢复、有界内存 |
| `cmd/dtsd` | 内存通道演示入口 |

## 判定语义

### 1. 状态聚合身份：系列根域（series root）

真实隧道工具把编码载荷放在**每次都不同的左侧标签**里，而父域保持稳定
（如 `x7f3…k2.tun.evil.test`、`q9ab…m1.tun.evil.test`）。因此基线与窗口状态
不按完整名、而按**系列根域**聚合（默认取最后两级标签；命中内置短公共后缀
`co/com/org/...` 时取三级）。特征仍从**完整名/最长标签**提取。这样同一隧道
的频率与重复编码特征才能累积，而不会把每次查询都当成全新序列。

### 2. 多维特征（绝不依赖单一特征）

每个事件计算以下特征，每个特征都同时有**绝对启发式信号**与**相对基线偏差
（z-score）**，取两者较强者：

- `length`：**最长标签**长度（编码载荷在单个超长标签内，而非多级合法名的总长）
- `entropy`：最长标签的归一化香农熵，且必须落在编码器典型区间
- `digit`：最长标签数字比例（base32/hex 载荷偏高）
- `rate`：查询频率（EWMA，事件/分）
- `interval`：平均查询间隔（稳定短间隔 = beaconing）
- `answer`：长名查询却返回极小应答
- `nxdomain`：长名查询反复 NXDOMAIN

**关键防误报耦合**：短标签上熵没有统计意义（`example` 7 个几乎不重复的字母
归一化熵也约 0.88）。因此 `entropy`/`digit` 只有在最长标签达到
`longLabelFloor`（默认 25）时才计入；`rate`/`interval` 这类纯行为特征只有在
存在长载荷标签时才加权。一个高频但名称短、可读的正常服务/批量任务**永远不会**
仅凭频率被告警。

### 3. 滑动窗口与疑似度累积

- 时间被切成固定宽度桶（默认 30s），窗口默认覆盖 300s（深度 10）。
- 每桶保留每个特征的**加权强度**（用于总分/严重度）和**未加权原始强度**
  （用于多特征门控，避免被权重大小影响）。
- 偶发异常不立即告警。`Advance(watermark)` 时同时满足以下全部条件才成警：
  1. 窗口内最长**连续异常桶**数 ≥ `MinSustainedBuckets`（默认 4）；
  2. 平均未加权强度达到 `featureGate`(0.5) 的**不同特征数** ≥ 2；
  3. 其中至少 1 个是载荷结构特征（长标签）；
  4. 加权总分 ≥ `MinSuspicionScore`。
- 空桶（时间缺口）得 0 分并打断连续 run，因此偶发/突发不会成警。
- **确定性与可重复性**：桶下标是 `UnixNano/width` 的纯函数；窗口下界只随
  watermark 推进；相同事件流 + 相同水位序列必然得到相同状态与结果。

### 4. 乱序与迟到

- 乱序到达（落到已存在的更早桶）只要仍在摄入容忍视界内就被接受，确定性地
  折叠进对应桶，不会错乱 lowest/highest。
- 超过 `LateToleranceSec`（默认 90s，折算成桶）的事件被拒绝并计入
  `RejectedLate`，不影响任何状态。
- 乱序时间戳不会污染速率/间隔 EWMA（`RateTracker.Observe` 对非递增时间返回
  false，该事件仍进入特征分布统计但不推进速率时钟）。

### 5. 告警去重、冷却与升级

告警身份是 `(客户端, 系列根域, "tunnel")`，由 `alert.Manager` 管理：

- 首次满足条件 → `AlertRaised`（一个有效告警，带唯一 ID）。
- 冷却期（`CooldownSec` 默认 600s）内条件持续、严重度不变 →
  `AlertRepeatedSuppressed`，**保留同一条有效告警**，仅累加 `Suppressed` 计数。
- 冷却期内**严重度上升** → `AlertSeverityChanged`，产生**新的可区分告警**，
  并记录 `Previous` 严重度。
- 冷却到期而条件仍持续 → `AlertReopened`，产生新 ID（重复行为可由
  `FiredCount`、`LastFiredAt`、`CooldownUntil` 解释）。
- 条件消失则去活；若在冷却内再次出现仍被抑制，杜绝靠“闪断”刷告警。
- 出现一个**新的隧道根域**（不同身份）会产生独立告警，不被旧身份吞掉。

### 6. 白名单、豁免与基线漂移

- **白名单（whitelist）**：对完整名与系列根域都匹配；命中后完全不学习、不
  打分、不入窗。对根域也校验是为了防止白名单主机的长名被聚合进共享父域而
  “污染”正常域基线。
- **豁免（exemption）**：仍纳入基线学习（保持漂移适应），但永不告警——用于
  已知心跳域名、经批准的批量任务。支持域名后缀与正则。
- **基线漂移**：分布统计按时间常数 `DriftTauSec`（默认 1800s）做指数衰减；
  长期合法变化（新批任务、客户端升级后名称变长）会被逐步吸收而非持续误报。

### 7. 配置更新不混用新旧规则

- `config.Store` 原子地服务**不可变快照**（深拷贝，含编译后的正则），并维护
  单调递增的 generation；持有旧快照的评估始终用旧规则跑完，新事件/新窗口用新
  快照。正则非法时 `Replace` 返回错误且**不**推进代次、保留旧配置。
- 每个窗口记录创建时的 `CfgGen`；持久化也保存它，避免跨更新在同一窗口内混用
  新旧权重。

### 8. 高吞吐并发与有界内存

- 按客户端 IP 的 FNV 哈希把状态分片到 N 个 shard（默认构造参数，clamp 到
  [1,64]）；同一客户端的所有状态只由一个 shard 串行拥有，无粗粒度全局锁。
- 两种摄入模式：
  - `Start` 前 / `Close` 后：`Ingest` 在分片锁内**同步内联**处理（确定性强，
    便于测试与嵌入式内存驱动）；
  - `Start` 后：进入有界 mailbox（4096/shard），满了则**丢弃并计数**而非阻塞
    调用方。
- 有界：`MaxClients`/`MaxNames` 用 LRU 限制基数；后台周期清理空闲窗口、基线
  与过期告警状态，长期运行不会因历史状态无限增长。

### 9. 持久化与崩溃恢复

- 周期性（`PersistPeriodMS`，默认 2000ms）以及优雅 `Close` 时，把窗口桶
  （含加权与原始强度）、cfgGen 与全部告警状态写入快照。
- 写入采用“临时文件 + fsync + 原子 rename + 目录 fsync”，崩溃只会留下旧文件
  或完整新文件；缺失文件视为全新空状态；格式带 `version`。
- 重启后 `Restore`：
  - 已触发告警的冷却/去活状态被恢复 → **冷却内不重复告警**；
  - 窗口累积（含原始门控强度）被恢复 → 跨重启窗口内的**持续异常不会丢失**，
    冷却到期后按语义恰好 reopen 一次。

## 配置项参考（`config.Config` / `Thresholds`）

| 字段 | 默认 | 含义 |
|---|---|---|
| `WindowSizeSec` | 300 | 滑动窗口时长 |
| `BucketWidthSec` | 30 | 桶宽；窗口深度 = 窗口/桶宽 |
| `LateToleranceSec` | 90 | 迟到事件容忍视界 |
| `CooldownSec` | 600 | 同一身份告警冷却 |
| `MaxClients` / `MaxNames` | 10000 | 客户端 / 每客户端名称基数上限（LRU） |
| `FeatureWeights` | length 1.0, entropy 1.2, digit 0.8, rate 1.0, interval 0.8, answer 0.6, nxdomain 0.6 | 各特征权重；0 表示禁用该特征 |
| `MinBaselineSamples` | 20 | 基线预热样本数；未达时仅记录结构绝对信号 |
| `MinNameLength` | 40 | 全名长度（应答/NXDOMAIN 子特征的门槛） |
| `MinEntropy`/`MaxEntropy` | 0.8 / 1.0 | 编码器典型熵区间 |
| `MinRatePerMinute` | 30 | 频率绝对下限 |
| `MaxMeanIntervalMS` | 2500 | 平均间隔低于此值可计 beaconing |
| `MinSuspicionScore` | 2.0 | 桶异常 / 成警总分门限 |
| `MinSustainedBuckets` | 4 | 窗口内所需连续异常桶数 |
| `HighScore` / `CriticalScore` | 3.5 / 5.0 | 严重度分级阈值 |
| `DriftTauSec` | 1800 | 基线指数漂移时间常数 |
| `Whitelist` / `Exemptions` | — | 规则列表（`ClientIP`/`NameSuffix`/`NameRegexp`，空字段为通配） |
| `PersistPath` | 空 | 快照文件路径；空表示禁用持久化 |
| `PersistPeriodMS` | 2000 | 后台快照周期 |

## 使用示例

```go
cfg := config.Default()
cfg.PersistPath = "/var/lib/dtsd/state.json"
cfg.Exemptions = []config.Rule{{NameSuffix: "heartbeat.internal"}}

out := make(chan model.AlertUpdate, 128)
d := detector.New(cfg, 8, out)
d.Start(context.Background())
defer d.Close()

d.Ingest(model.Event{
    Time:     time.Now(),
    ClientIP: "10.0.0.9",
    Name:     "x9f2…aa1.tun.evil.test",
    Response: &model.DNSResponse{Observed: true, NXDOMAIN: true, AnswerBytes: 12},
})

// 热更新（非法正则会返回错误并保留旧配置）
_ = d.UpdateConfig(newCfg)
```

`AlertUpdate.Kind` 区分 `AlertRaised / AlertSeverityChanged /
AlertRepeatedSuppressed / AlertReopened`，sink 可据此只对有效告警发声、
对抑制做计数或审计。

## 测试覆盖

- `window`：桶下标确定性、迟到边界、乱序不乱序、推进幂等可重复、空桶打断
  run、快照往返。
- `features`：熵已知值、Welford 均值/方差、衰减保均值、乱序不污染速率。
- `baseline`：客户端/名称隔离、漂移适应、名称/客户端上限 LRU、过期清理。
- `config`：后缀边界匹配、白/豁免、代次递增、坏正则被拒、快照不可变。
- `alert`：raise/抑制/reopen、冷却内升级、新特征独立、消失后冷却仍生效。
- `persist`：缺失文件、原子往返、临时文件清理、坏数据报错。
- `detector`：多维特征组合成警、偶发异常静默、冷却去重与到期 reopen、严重度
  升级、白名单/豁免、乱序/迟到、**重启恢复（不重复且不漏报）**、并发摄入、
  有界 mailbox 丢弃、配置热更、阈值边界，以及真实 `Start` + 文件持久化的
  端到端场景。
