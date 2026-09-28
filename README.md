# dtsd — 本地 DNS 隧道流量检测与告警服务

`dtsd` 消费带时间戳的 DNS 查询事件流（来自本地回环、文件或内存通道），
识别 DNS 隧道行为并输出**去重、带冷却**的告警。它不依赖任何外部服务或
真实凭据：全部判定在进程内完成，状态落在本地 WAL + 快照文件。

## 特性与需求对应

| 需求 | 实现 |
| --- | --- |
| 1. 多维特征 + 可演进基线 | `internal/features` 抽取长度/熵/标签/数字比例/响应特征；`internal/baseline` 对每个客户端与查询名维护 EWMA 均值-方差基线与按桶 QPS |
| 2. 滑动窗口 + 疑似度累积 | `internal/window` 以事件时间对齐固定桶，同时要求总分 `fire_score` **且**活跃桶数 `fire_buckets` 达标，偶发异常不告警；时间只来自事件时间戳，确定可重复 |
| 3. 告警去重与冷却 | `internal/alerting` 以 `(客户端, 隧道特征父域)` 为身份做冷却；严重度升级产生新告警；冷却到期再告警带 `cooldown_expired_refire#N` 解释；新特征独立告警 |
| 4. 白名单 / 豁免 / 漂移 | `internal/config` 编译不可变规则快照（后缀按标签匹配 + 正则 + 客户端），`SIGHUP`/`UpdateConfig` 生成新代际；EWMA 基线随合法行为漂移；心跳低 QPS 豁免 |
| 5. 高吞吐并发 + 有界内存 | `internal/detector` 按客户端哈希分片，每分片单 goroutine 无锁状态；有界队列背压（`ErrQueueFull`）；窗口推进、基线/告警空闲淘汰、容量上限保证内存有界 |
| 6. 持久化与崩溃恢复 | `internal/persist` 先写 WAL 再应用；周期原子快照；恢复时加载最新快照并重放其后 WAL。判定是事件序列的纯函数，重放后告警 ID 稳定：不重复、不漏跨重启持续异常 |
| 7. 测试与文档 | 每个包均有单测/集成测试，覆盖特征组合、阈值边界、冷却、豁免、乱序迟到、背压、重启恢复 |

## 判定语义

### 事件时间模型

所有窗口与时间判断都使用 `Event.TS`，绝不使用墙上时钟。维护循环只决定
“何时运行”，截止时间仍来自水位（最高已见事件时间），因此：

- 同一条事件序列无论何时喂入，结果完全一致（测试与重放依赖这一点）；
- **乱序事件**在其所属桶内正常聚合；
- **迟到事件**若早于 `水位 - (window.size + lateness_grace)` 则被丢弃
  （对应桶已终结），其余照常计入；晚于水位的事件才更新基线统计，迟到
  事件不会污染可演进基线。

### 多特征评分（单事件）

评分在基线更新**之前**进行，即与“不含当前事件”的历史比较：

1. **名称长度**：超过绝对阈值 `name_len_abs_threshold`，或显著高于该客户端 EWMA 基线（z 分）。
2. **字符熵**：超过绝对熵阈值，或高于基线。
3. **数字比例** / **最长标签**：相对基线的正偏离。
4. **查询频率**：当前滑桶 QPS 超过 `freq_qps_threshold` 且高于心跳速率 `heartbeat_max_qps`；周期性低速率心跳永不触发。
5. **查询间隔**：间隔显著短于该客户端基线（突发隧道）。
6. **响应特征**：NXDOMAIN（基线 NX 率高时加强）、有响应无应答——故意设为弱信号，避免单凭响应特征误报。

每个信号强度按 `权重 × 截断后的偏离强度` 累加，单事件总分截断于
`max_suspect_score`。**任一单一信号都不足以立即告警**。

### 隧道身份与窗口累积

隧道特征身份取查询名的最后两个标签（`a3f…x.evil.io → evil.io`），同一
隧道的不同随机子域聚合到同一状态。分数按 `slide` 桶累加；仅当滑动窗口内
**总分 ≥ `fire_score` 且活跃桶数 ≥ `fire_buckets`** 才触发，严重程度随
相对强度与活跃桶覆盖度分 low/medium/high/critical。

### 去重 / 冷却 / 升级

身份为 `(client_ip, tunnel_key)`，在冷却窗口内：

- 重复证据 → 抑制并计数（可观测被抑制次数）；
- 严重度升级（且 `escalate_on_severity_change=true`）→ 产生可区分的新告警并重置冷却；
- 新特征父域 / 新客户端 → 独立告警；
- 冷却到期后的重复 → 新 ID 新告警，原因含 `cooldown_expired_refire#N`，行为可解释。

告警 ID 形如 `client|key|firstTS-unixnano|severity`，是事件序列的确定函数，
因此崩溃重放产生相同 ID，天然不重复。

### 白名单与配置代际

- 后缀按 **DNS 标签**匹配：`example.com` 豁免 `a.example.com`，但不豁免 `notexample.com`；
- 正则在配置加载时编译，非法正则会使加载失败；
- 配置更新分配新的不可变快照（`Gen` 递增）。每个事件原子地引用一个代际评估；
  旧窗口在其自然过期前不与新规则混用，新事件立即按新规则评估。

### 内存有界

- 窗口 `Advance` 丢弃越界桶并回收空状态；
- 基线按空闲时间与 `max_baseline_keys` 上限淘汰；
- 告警冷却过期即删除，并受 `max_active_keys` 约束；
- 摄入队列有界，满时 `Submit` 返回 `ErrQueueFull` 而非无限增长。

### 持久化与恢复

```
接受事件 → fsync 追加 WAL → 应用到内存状态 → (每 snapshot_every_events) 原子快照+截断 WAL
启动     → 读取最新快照 → 按快照 seq 重放其后 WAL（同一确定性管线）
```

- 快照写临时文件后 `rename`，崩溃只留下旧快照或完整新快照；
- WAL 末尾撕裂行（崩溃写了一半）自动按 EOF 容忍；
- WAL seq 全局单调，快照截断后从快照 seq 继续，重放过滤 `seq <= snapshot_seq`。

## 配置项

JSON（时间字段为 Go duration **纳秒整数**），见 [`configs/example.json`](configs/example.json)。
省略字段使用 `config.Default()` 默认值；未知字段会被拒绝以防拼写错误。

| 段 | 键 | 含义 |
| --- | --- | --- |
| `window` | `size` / `slide` | 窗口总时长 / 桶宽 |
| | `fire_score` / `fire_buckets` | 触发的总分与最少活跃桶数双门槛 |
| | `max_suspect_score` | 单事件得分上限 |
| | `lateness_grace` | 水位之后允许迟到的宽限 |
| `scoring` | `w_*` | 各信号权重（长度/熵/数字/频率/间隔/NX/无应答/长标签） |
| | `name_len_abs_threshold` / `entropy_abs_threshold` / `freq_qps_threshold` | 绝对阈值 |
| `baseline` | `min_samples` | 基线可信所需样本数（此前只用绝对阈值） |
| | `ewma_alpha` | EWMA 自适应速度（0,1]，越大越快漂移 |
| | `drift_z_factor` / `drift_cap` | z 分容忍带与单信号最大贡献 |
| | `heartbeat_max_qps` | 低于此 QPS 的周期流量视为心跳，不判高频 |
| | `max_baseline_keys` | 客户端/名称基线条目上限 |
| `cooldown` | `duration` | 去重冷却时长 |
| | `escalate_on_severity_change` | 严重度升级是否产生新告警 |
| | `max_active_keys` | 存活告警身份上限 |
| `whitelist` | `suffixes` / `regexps` / `clients` | 域名后缀 / 正则 / 客户端豁免 |
| `ingest` | `shard_count` / `queue_size` / `max_tracked` | 分片数、每分片队列容量、跟踪上限 |
| `persistence` | `dir` | WAL/快照目录（空则禁用持久化） |
| | `snapshot_every_events` | 每处理多少事件做一次快照 |
| | `wal_max_bytes` / `flush_interval` | WAL 大小目标 / 刷盘调度间隔 |

## 使用

```bash
# 输入：每行一个 DNS 事件 JSON（ts 为 RFC3339）
cat events.jsonl | go run ./cmd/dtsd -config configs/example.json -state-dir ./var/state
```

事件示例：

```json
{"ts":"2026-09-28T10:00:00Z","client_ip":"10.0.0.9","qname":"x3fa….evil.io","qtype":"A","rcode":"NXDOMAIN","ans_count":0}
```

输出：每行一个去重告警 JSON（含稳定 `id`、严重度、分数、触发原因与样本名）。

信号：`SIGHUP` 热加载配置（新代际，旧窗口自然过期）；`SIGINT/SIGTERM`
刷最终快照后退出。

## 测试

```bash
go test ./...          # 全部单测与集成测试
go test -race ./...    # 并发竞态检测
```

测试覆盖：熵/特征抽取、EWMA 漂移与淘汰、窗口阈值边界与确定性、乱序与迟到
接受/丢弃边界、冷却抑制/升级/到期再告警、白名单后缀与正则、高吞吐并发与
背压、WAL/快照截断与撕裂行容忍、跨重启不重复告警且不漏窗口内持续异常。
