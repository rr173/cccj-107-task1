# 多地域边缘策略传播控制服务（Policy Propagation Controller）

把策略配置按**作用域依赖**安全传播到多地域边缘节点的控制面 + 边缘代理。
全部代码仅依赖 **Python 3.11 标准库**（`http.server` / `sqlite3` / `urllib`），
镜像构建无需联网安装任何包。

## 它解决了什么

| 需求 | 实现 |
| --- | --- |
| 配置按作用域组成依赖，子项必须等父版本抵达后才生效 | 发布时校验祖先作用域链；版本携带 `deps={scope: version_id}`；节点与控制端双重**激活闸门**（父版本曾抵达 `ACTIVATED/REPLACED/SUPERSEDED`） |
| 撤销尚未完全扩散的版本 | `POST /v1/versions/{id}/revoke`；任一节点**曾激活过**即 409 拒绝（只能用新版本/覆盖纠正）；未激活的，节点下轮 pull 收到 `RECALL` |
| 针对少数地域的紧急覆盖 | 发布 `override=true + target_regions/target_nodes`；仅命中目标节点；激活后旧激活版本记 `SUPERSEDED`（普通升级记 `REPLACED`） |
| 长离线重连必须拿到从本地版本安全前进的链 | `plan_chain` 从每个作用域“最高已激活水位 +1”开始，同作用域按 seq 逐个给、跨作用域拓扑排序；**绝不直接发最新快照**；已撤销版本先 `RECALL` |
| 回执可重复、可乱序，状态不能倒退 | 每节点单调 `seq` + 高水位：旧序拒绝、空洞拒绝、完全重复幂等；状态有秩（DOWNLOADED&lt;VERIFIED&lt;ACTIVATED&lt;终态），倒退拒绝；哈希不符拒绝 |
| 区分 已下载/已校验/已激活/被覆盖 | `DOWNLOADED → VERIFIED → ACTIVATED → SUPERSEDED | REPLACED | REVOKED`，节点与控制端双侧状态机；pull 带 `reconcile` 做崩溃对账 |
| 可执行的容器环境 | 单镜像 + docker compose（1 控制面、cn/eu/us 3 个在线边缘、1 个晚到离线节点）、健康检查、持久化卷 |

## 架构

```
                ┌──────────────────────────────┐
发布/撤销/覆盖   │  controller (FastAPI-less,    │      轮询 pull(本地状态)
──────────────▶ │  stdlib http.server + SQLite) │ ◀───────────────────────┐
                │                              │                         │
                │  plan_chain: 依赖拓扑安全链     │   ops: [APPLY|RECALL]   │
                │  decide_receipt: 序号+状态秩   │ ───────────────────────▶│
                │  can_revoke: 扩散闸门          │                         │
                └──────────────────────────────┘   receipts(seq 递增)    │
                                                        ────────────────▶ │
                                                              edge-cn / eu / us / late
```

边缘节点（`app/agent.py`）本地持久化一个 JSON：
```json
{"next_seq": 7,
 "versions": {"base@1": {"state": "REPLACED", "sha": "…"},
              "policy@4": {"state": "ACTIVATED", "content": "…", "sha": "…"}}}
```
- 每轮 pull 上报全部本地版本状态，控制端结合**已观测状态**合并规划（崩溃/乱序都不会让链断裂）。
- 每条 `APPLY` 在节点侧顺序执行：内容 sha256 + HMAC 签名校验 → `DOWNLOADED` → `VERIFIED` → 父依赖抵达后 `ACTIVATED`。
- 回执严格按本地 `next_seq` 发送（at-least-once）；控制端去重，网络失败重试。
- pull 响应中的 `reconcile` 让节点在重启/漏发级联回执后自动对齐（只推进不回退，撤销除外）。

### 为什么链里一个操作会出现多条版本
一次重连返回的链形如：
```
base@1 → base@2(被 policy@1 依赖的那个版本) → policy@1 → base@3 → policy@3 → policy@4(覆盖)
```
同作用域严格按版本号，跨作用域按“父版本先于子版本”。中间版本不跳过——
子版本可以声明依赖**旧的**父版本（如 `policy@1 deps base@1`），只要该父版本曾安全抵达，
闸门即满足；父版本之后被新版本替换（`REPLACED`）不影响子版本的有效性。

## API

| 方法 路径 | 说明 |
| --- | --- |
| `POST /v1/scopes` | `{name, parent?}` 声明作用域及父作用域 |
| `POST /v1/versions` | 发布。普通：`{scope, content, deps?, parent_scope?}`；紧急覆盖：额外 `override:true, target_regions:[…]` 或 `target_nodes:[…]`（不指定目标拒绝） |
| `POST /v1/versions/{id}/revoke` | 撤销未扩散版本；已在任一节点激活过 → 409 |
| `POST /v1/nodes/{id}/pull` | `{region, present:{vid:state}}` → `{ops, blocked, reconcile, high_water}` |
| `POST /v1/nodes/{id}/receipts` | `{region, seq, version_id, state, sha256?}` → `{accepted, reason, high_water, duplicate}` |
| `GET /v1/versions` | 版本 × 节点的传播矩阵 |
| `GET /v1/nodes` / `GET /v1/nodes/{id}` | 节点总览 / 节点状态+回执日志 |
| `GET /healthz` | 健康检查 |

`APPLY` 操作自带 `content / content_sha256 / signature(HMAC-SHA256) / deps / override`，
节点离线期间不需要任何额外下载通道。

## 快速开始（容器）

```bash
make up            # 或 docker compose up -d --build
docker compose logs -f edge-cn
make down          # 清理
```

## 一键演示

```bash
make demo          # 等价 ./demo.sh（需要 docker compose v2）
```

演示脚本逐步展示：
1. 声明 `system ← base ← policy` 作用域链并发布 v1；
2. 三地节点完成 `下载→校验→激活`，子版本等父版本；
3. 发布 base@2/policy@2 后**立即撤销** base@2 —— 节点只会收到 `RECALL`，policy@2 永久 blocked；同时演示“已激活版本不可撤销”被 409 拒绝；
4. 发布 base@3/policy@3，再对 `region=cn` 发紧急覆盖 policy@4 —— cn 上 policy@3 变 `SUPERSEDED`，eu/us 完全收不到覆盖；
5. 拉起长时间离线的 `edge-late-cn`，从日志可看到它按完整有序链前进（跳过已撤销的 base@2），而不是直接领取 policy@4；
6. 对探针节点重放**旧回执 / 乱序空洞 / 错误哈希 / 状态倒退**，全部被拒；完全重复回执幂等。

不想用容器时，也可以直接跑控制面和代理：
```bash
python3 app/server.py                                   # :8080
SIGNING_SECRET=shared-demo-secret \
  python3 app/agent.py --id n1 --region cn \
  --controller http://127.0.0.1:8080 --state-file ./data/n1.json
python3 scripts/demo_client.py --base http://127.0.0.1:8080 bootstrap
```

## 测试（无需容器、无第三方依赖）

```bash
make test          # = test-unit + test-e2e
```

- `tests/test_core.py`：安全更新链（含离线重连、覆盖定向、撤销裁剪）、回执序号/哈希/倒退/级联判定、撤销闸门；
- `tests/test_service.py`：发布校验、完整三态回执生命周期、撤销与 RECALL、覆盖只命中目标地域；
- `tests/test_e2e.py`：真实启动 HTTP 控制面 + 代理子进程，跑发布→撤销→覆盖→晚到节点重连→回执攻击全链路。

## 关键设计取舍

- **“父版本抵达”定义为曾激活**（ACTIVATED 或之后 REPLACED/SUPERSEDED），而非当前仍 ACTIVATED；
  否则同一条链中 base@1 被 base@2 替换后，依赖 base@1 的 policy@1 会被误拒。REVOKED 不算抵达。
- **撤销是控制端闸门 + 节点回收两段式**：控制端只允许在“没有任何节点曾激活”时撤销；
  已经下载/校验中的节点在 pull 时收到 `RECALL` 丢弃本地副本，绝不允许其激活。
- **序号水位只在“恰好下一个序号”时推进**（无论该回执被接受还是被确定性拒绝——拒绝结论也是确定事实）；
  旧序号/空洞永不推进，旧回执无法把任何状态拉回去。
- **链规划是无状态纯函数**（`app/core.py`），输入全量版本 + 节点本地快照，输出操作链；
  所有 IO/事务集中在 `service.py`，核心语义可直接单测。
- 配置内容的完整性用 sha256，来源用 HMAC-SHA256（共享密钥，环境变量 `SIGNING_SECRET`，生产应替换为每节点密钥/非对称签名）。
