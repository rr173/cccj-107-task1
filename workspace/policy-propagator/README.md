# policy-propagator

把策略配置安全传播到多地域边缘节点的控制服务。**纯 Python 标准库**（HTTP +
SQLite），无第三方依赖，容器可离线构建。

## 要解决的问题与对应机制

| 需求 | 机制 |
|---|---|
| 配置按作用域（scope）构成依赖，子项只能在父版本到达节点后生效 | 版本有 `parent`（同作用域主线）与 `requires`（跨作用域依赖）；激活前服务端和节点都检查 **激活门**：所有依赖必须处于 `ACTIVATED`/`OVERRIDDEN` |
| 撤销尚未扩散完成的版本 | `revoke` 仅在**从无节点激活**且**无存活后继**时允许；在途副本统一置 `PURGED` 并 `epoch+1`，节点收到 purge 指令删除本地副本 |
| 面向少数地域的紧急覆盖 | `kind=override` + `regions=[...]`，从当前主线头分叉；仅命中地域下发，且**新主线版本不会自动顶替仍然生效的 override** |
| 长期离线节点重连得到安全更新链而非最新快照 | poll 时从节点上报的本地活动版本沿 `parent` 向上收集到 desired，逐版本下发（拓扑序，父先子后）；基线不在 desired 祖先链上时直接拒绝，不做隐式重置 |
| 回执可能重复、乱序 | 回执带稳定 `receipt_id`，服务端永久留存并去重、**重放原裁决**；状态机只允许逐格前进，跳格/倒退均拒绝 |
| 准确区分 已下载/已校验/已激活/被覆盖 | 单调阶梯：`PENDING → DOWNLOADED → VERIFIED → ACTIVATED → OVERRIDDEN`（撤销路径为 `PURGED`） |
| 阻止旧回执让进度倒退 | 每条 node-version 有 `epoch` 围栏：撤销、服务端自动覆盖、本地丢包重武装都会 bump；旧 epoch 回执一律 `stale epoch` 拒绝；低 rank 回执 `stale receipt ... backwards` 拒绝 |

内容完整性：发布时计算 sha256；`DOWNLOADED` 只是节点的持有声明，
`VERIFIED` 必须回传与控制端一致的摘要，否则拒绝并无法激活。

## 架构

```
app/                    控制面
  states.py             状态阶梯与常量
  db.py                 SQLite schema / 连接
  service.py            全部领域逻辑（发布/撤销/poll/回执/更新链）
  server.py             stdlib http.server 薄 HTTP 层
  main.py               入口
edge/agent.py           边缘节点：轮询、按链下载/校验/激活、回执持久化重发、
                        purge、本地激活门；9000 管理口（断网/冻结/注入回执）
scripts/ppcli.py        控制端 CLI
scripts/e2e_demo.py     启动 1 控制端 + 3 真实边缘 agent 的端到端验证
tests/test_service.py   17 个领域不变量单元测试
```

状态持久化：控制端 SQLite（WAL）+ 按版本 id 存放的 blob；边缘节点
`state.json` + blobs + 原子替换的 `active/<scope>.conf`。

## 容器方式运行

```bash
docker compose up --build
# 控制端 http://localhost:8080
# 三个节点管理口：9001(eu) 9002(us) 9003(apac)
```

compose 会起 control 与 `eu/us/apac` 三个边缘节点，各自挂载独立数据卷。

发布一个版本：

```bash
# 跨作用域依赖
printf 'runtime-1' > /tmp/rt
printf 'app-1'     > /tmp/app
PP_URL=http://localhost:8080 python3 scripts/ppcli.py publish runtime --file /tmp/rt
PP_URL=http://localhost:8080 python3 scripts/ppcli.py publish app \
    --file /tmp/app --requires runtime-v1

# 仅 eu 的紧急覆盖
printf 'HOTFIX' > /tmp/hot
PP_URL=http://localhost:8080 python3 scripts/ppcli.py publish app \
    --file /tmp/hot --kind override --regions eu

# 撤销尚未扩散的版本
PP_URL=http://localhost:8080 python3 scripts/ppcli.py revoke app-v3
```

查看节点实际生效内容与状态：

```bash
curl localhost:9001/active            # 节点上各 scope 的生效配置
curl localhost:8080/nodes/edge-eu-1   # 控制端视角的版本状态
```

模拟断网/重连/乱序回执（演示用管理口）：

```bash
curl -X POST localhost:9003/mode -d '{"offline": true}'   # 断开节点
curl -X POST localhost:9003/mode -d '{"offline": false}'  # 重连
curl localhost:9003/state                                 # 观察更新链 plan
# 直接注入一条乱序/旧 epoch 回执
curl -X POST localhost:9001/send-receipt -d \
  '{"version":"app-v3","state":"ACTIVATED","epoch":1}'
```

## 端到端验证（无需 docker）

`scripts/e2e_demo.py` 会在本机启动 1 个控制端和 3 个**真实**边缘 agent 子进程，
依次验证：依赖门顺序滚动、离线节点拿到有序链 `[v2,v3,...]`、撤销在途版本并
fence 旧回执、eu-only override 不被新主线顶替、重复/乱序/坏哈希/倒退回执全部
被正确处理：

```bash
python3 scripts/e2e_demo.py
python3 -m unittest tests.test_service -v
```

## HTTP API

| 方法 路径 | 说明 |
|---|---|
| `POST /scopes` `{name}` | 创建作用域 |
| `POST /versions` | 发布；字段：`scope, content_b64, kind=base|override, regions?, requires[], parent?` |
| `POST /versions/{id}/revoke` | 撤销未扩散版本 |
| `GET /versions[?scope=]` / `GET /versions/{id}` | 版本查询 |
| `GET /blobs/{id}` | 下载内容（撤销后 404） |
| `POST /nodes` `{node_id, region}` | 节点注册/心跳 |
| `POST /nodes/{id}/poll` | 上报本地版本与活动版本，返回 `desired / plan(有序) / purge / current` |
| `POST /nodes/{id}/receipts` | 回执：`{receipt_id, version, state, epoch, content_sha?}`，返回 `accepted/reason/duplicate` |
| `GET /nodes` / `GET /nodes/{id}` | 扩散状态视图 |

### poll 返回的 plan 元素

```json
{"version":"app-v2","scope":"app","seq":2,"kind":"base","parent":"app-v1",
 "requires":["runtime-v3"],"content_sha":"…","size_bytes":5,
 "blob_url":"/blobs/app-v2","epoch":1}
```

节点严格按数组顺序推进，每项必须下载→（比对 sha）校验→（本地依赖门）激活，
回执失败按同一 `receipt_id` 重发。

## 关键安全语义说明

- **override 存活规则**：某地域存在命中的未撤销 override 时，desired 仍是该
  override；主线继续向前只影响其他地域。要收回热补丁，发布同地域新 override 或
  直接发布把补丁内容合入的新 base（之后可撤销旧 override，前提是它没在任何
  节点激活过——已激活的覆盖只能被后继顶替，不能删除）。
- **撤销不是删除历史**：已激活的版本不可撤销（会 409），只能发布后继；这保证
  依赖链不会出现空洞。`PURGED` 仅针对在途（PENDING/DOWNLOADED/VERIFIED）副本。
- **OVERRIDDEN 由服务端裁定**：新版本激活时服务端自动把同作用域旧活动版本置为
  OVERRIDDEN 并 bump 其 epoch，节点本地同步标记即可，无需也不能用旧 epoch 回执
  驱动该转换。
