# 结构化输出与速率控制

本文档说明 gobuster 的结构化输出（JSONL）、两级速率控制、运行时动态调整与自适应降速的字段口径、配置项、接口与并发写策略。

## 一、结构化输出（JSONL）

### 启用方式

```bash
gobuster dir -u https://target.example/ -w words.txt \
  -o text-report.txt \                      # 现有文本输出，行为不变
  --output-structured hits.jsonl            # 新增：结构化输出
```

两种输出可同时开启，互不影响：文本格式逐字节保持原样，结构化记录只写入 JSONL 文件，不会混入终端进度显示（进度走 stderr，结果走 stdout，JSONL 走文件）。

### 字段口径（schema 固定）

每行一个 JSON 对象，**字段名、顺序与嵌套层级固定**（由 `libgobuster.StructuredResult` 的结构体字段顺序决定，不得变更）：

| 字段 | 类型 | 口径 |
|---|---|---|
| `timestamp` | string | 命中时间，RFC3339Nano（含时区），由产生结果的 worker 记录 |
| `plugin` | string | 插件名，取自 `plugin.Name()`，如 `directory enumeration` |
| `target` | string | 本轮扫描的基础目标，如 `http://127.0.0.1:8080/`；dns 模式为域名，tftp 模式为服务器地址 |
| `path` | string | 命中的路径 / 单词 / 子域名 / bucket 名（去掉文本输出中的对齐空格） |
| `status_code` | int | HTTP 状态码；非 HTTP 类插件（dns/gcs/s3/tftp）固定为 `-1`；dir 模式开 `--no-status` 时也为 `-1` |
| `length` | int64 | 响应体字节数；不可用或 `--hide-length` 时为 `-1` |
| `redirect` | string | `Location` 响应头的值，无重定向时为空字符串 `""` |
| `duration_ms` | int64 | 该请求（含其内部重试）的墙钟耗时，毫秒 |
| `is_new` | bool | `true` = 本轮新增命中；`false` = 历史已确认（见下） |

示例（一次运行同时产出两种输出）：

```
# 终端 / -o 文本
admin                (Status: 200) [Size: 12]

# hits.jsonl 中的一行
{"timestamp":"2026-11-18T11:40:30.340662496+08:00","plugin":"directory enumeration","target":"http://127.0.0.1:18234/","path":"admin","status_code":200,"length":12,"redirect":"","duration_ms":1,"is_new":true}
```

### 下游解析方式

逐行解析即可，每行是独立 JSON，无需整体加载：

```bash
# 只取本轮新增命中，喂给 SIEM
jq -c 'select(.is_new == true)' hits.jsonl

# 按状态码聚合
jq -r '.status_code' hits.jsonl | sort | uniq -c
```

```python
import json
for line in open("hits.jsonl"):
    rec = json.loads(line)          # 字段名固定，直接按键取
    if rec["is_new"]:
        send_to_siem(rec)
```

### 追加合并与 `is_new` 判定

- 文件以 `O_APPEND` 打开，**多次运行、多个进程的结果都追加到同一文件**，不会互相覆盖。
- 启动时会读取已有文件，建立「已确认命中」集合，键为 `plugin + target + path + status_code`。
- 每条结果写入前比对集合：已存在 → `is_new=false`（历史已确认）；不存在 → `is_new=true` 并在写盘成功后加入集合（同一轮内重复命中也只算一次新增）。
- 写盘失败的记录**不会**被标记为历史，下次运行仍会作为新增上报。
- 历史文件中无法解析的行会被跳过（可能是其他工具写入的），不会导致启动失败。

### 并发写策略

- **进程内**：单个 `StructuredWriter`，互斥锁串行化所有写入。
- **进程间**：文件以 `O_APPEND|O_CREATE|O_WRONLY` 打开，每条记录（JSON + `\n`）用**一次 `write()` 系统调用**落盘。`O_APPEND` 保证每次写入原子地落到文件末尾，多进程并发追加不会互相覆盖、不会出现半行交错。
- 字段顺序由 Go 结构体序列化保证，同一版本二进制输出的 key 顺序恒定。

### 写入失败

打开失败（目录不存在、无权限）时**启动即报错退出**（退出码 2）；运行中写盘失败时会打印 `[ERROR]`、**立即中止扫描**并以退出码 2 退出，绝不静默丢结果。

## 二、速率控制

### 配置项

| 参数 | 默认 | 说明 |
|---|---|---|
| `--rate-limit` | 0（不限） | 全局请求速率上限，次/秒 |
| `--rate-limit-per-target` | 0（不限） | 按目标（host）的速率上限，次/秒 |
| `--rate-control-file` | 空 | 运行时动态调整的控制文件路径（JSON） |
| `--rate-adaptive` | false | 遇到限流响应自动降速、恢复后缓慢提速 |
| `--rate-min` | 1 | 自适应降速的下限，次/秒 |

### 语义

- **排队不丢弃**：超出速率的请求在各自的 worker 里等待令牌，不会丢弃、不会阻塞整个协程池（每个等待者睡在自己的定时器上，预订式令牌桶）。
- **两级冲突取更严**：全局与按目标同时配置时，每个请求要先后通过两个限流器，实际生效的是更严格的那个。原因：两者是串联取令牌而非取并集，瓶颈自然由较小的速率决定（实测：全局 100 + 单目标 25 → 实际 24.9 req/s）。
- **作用范围**：限速作用于所有基于 HTTP 的插件（dir/vhost/fuzz/gcs/s3），dns、tftp 插件不受影响。
- 与既有 `--delay`（每线程固定间隔）互不干扰，默认值均未改动。

### 运行时动态调整

启动时指定 `--rate-control-file ctl.json`，gobuster 每秒检查一次文件变更（按 mtime），无需重启进程：

```json
{"global_rps": 200, "per_target_rps": 50}
```

- 两个键都可省略，省略的维度保持原值；设为 `0` 表示关闭该维度限速。
- 文件解析失败时保留当前速率并输出 `[WARN]`。
- **正在等待的请求不会被挂死**：速率变更会唤醒所有等待者，按新速率重新排队。

### 自适应降速（AIMD）

开启 `--rate-adaptive` 后（需同时设置至少一个速率上限作为天花板）：

- **降速**：目标返回 `429` / `503` 或连接被重置时，当前速率乘以 0.5，下限为 `--rate-min`。
- **恢复**：连续 25 个成功响应且距上次降速超过 3 秒后，按 `max(1, 上限的5%)` 步进缓慢提速，直至回到配置上限。
- 同时，被限流/重置的请求按指数退避重排（500ms 起，翻倍至 5s 封顶，最多 4 次，尊重 `Retry-After` 头），**不会立刻记为不存在**；重试耗尽后按正常状态码规则判定。

### 调整审计日志

每一次速率变化（控制文件、自适应降速/提速、限速器启停）都会输出带时间点和原因的日志（stderr，`[INFO] [RATE]`），示例：

    [INFO] [RATE] 2026-11-18T11:43:04+08:00 scope=global rate 100.00 -> 50.00 req/s reason="target throttled the request (429/503/connection reset), decreasing rate"
    [INFO] [RATE] 2026-11-18T11:43:21+08:00 scope=global rate 2.00 -> 7.00 req/s reason="target recovered, slowly increasing rate"
    [INFO] [RATE] 2026-11-18T11:42:08+08:00 scope=global rate 20.00 -> 200.00 req/s reason="rate control file updated"

## 三、退出码

| 退出码 | 含义 |
|---|---|
| 0 | 正常运行完成，无命中 |
| 1 | 正常运行完成，有命中 |
| 2 | 运行错误（连接失败、输出文件写失败、参数错误等） |

调度系统可据此区分「有命中/无命中/出错」三种结局。

## 四、兼容性说明

- 未开启新参数时，文本输出格式、插件匹配判定逻辑、超时与重试默认值、终端进度显示均不变。
- 退避重排（429/503/连接重置的重试）仅在配置限速后启用，不改变默认行为。
- 未引入任何新的第三方依赖。

## 五、实测数据（本地 ratelab 测试服务，300 词字典，50 线程）

| 场景 | 墙钟时间 | 实测速率 |
|---|---|---|
| 不限速 | 0.22 s | 1343.8 req/s |
| `--rate-limit 50` | 6.07 s | 49.7 req/s |
| `--rate-limit-per-target 30` | 10.17 s | 29.7 req/s |
| 全局 100 + 单目标 25 | 12.12 s | 24.9 req/s（更严者生效） |
| 动态调整 20 → 200（第 4 秒写入控制文件） | 5.26 s | 无需重启即提速 |

自适应降速/恢复曲线（目标在第 40 个请求后开始返回 429，持续 5 秒）：

    11:43:04  100 → 50 → 25 → 12.5 → 6.25 → 3.12 → 2.0（触及 --rate-min 2）
    11:43:21  2 → 7 → 12 → 17 → 22 → 27 → 32 → 37 → 42 → 47 → 52（每步 +5，缓慢恢复）

限流窗口内的请求（如第 45 位的 `admin`）经退避重排后仍正确命中（`Status: 200`），未被误判为不存在；连接重置场景下 `/backup` 被重置 2 次后按 500ms→1s 退避重试成功。
