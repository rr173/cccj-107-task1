#!/usr/bin/env bash
# 一键演示：构建镜像 -> 起 1 控制面 + 3 地域边缘节点 -> 发布/撤销/覆盖 ->
# 拉起长离线节点验证安全更新链 -> 打印传播总览。
set -euo pipefail
cd "$(dirname "$0")"

BASE=${CONTROLLER_URL:-http://localhost:8080}

if ! docker compose version >/dev/null 2>&1; then
  echo "!! 需要 docker compose（Docker Desktop / Compose v2）" >&2
  exit 1
fi

echo "== 1/7 构建镜像并启动控制面 + cn/eu/us 三个边缘节点 =="
docker compose up -d --build controller edge-cn edge-eu edge-us

echo "== 等待控制面健康 =="
for i in $(seq 1 30); do
  if python3 scripts/demo_client.py --base "$BASE" health >/dev/null 2>&1; then
    echo "   controller healthy"; break
  fi
  sleep 1
done

echo
echo "== 2/7 声明作用域链 system <- base <- policy，并发布 v1 =="
python3 scripts/demo_client.py --base "$BASE" bootstrap

echo
echo "== 3/7 等待 cn/eu/us 完成 下载->校验->激活（含父子依赖闸门）=="
python3 scripts/demo_client.py --base "$BASE" wait-activated edge-cn policy@1 40
python3 scripts/demo_client.py --base "$BASE" wait-activated edge-eu policy@1 40
python3 scripts/demo_client.py --base "$BASE" wait-activated edge-us policy@1 40
python3 scripts/demo_client.py --base "$BASE" show

echo
echo "== 4/7 发布 base@2 + policy@2，但 base@2 尚未扩散即撤销 =="
python3 scripts/demo_client.py --base "$BASE" publish-and-revoke
sleep 4   # 让在线节点轮询一轮：只能收到对 base@2 的 RECALL，绝无激活
python3 scripts/demo_client.py --base "$BASE" show

echo
echo "== 5/7 发布 base@3 + policy@3（正常扩散），再对 cn 发紧急覆盖 policy@4 =="
python3 scripts/demo_client.py --base "$BASE" publish-v3-and-override
python3 scripts/demo_client.py --base "$BASE" wait-activated edge-cn policy@4 40
python3 scripts/demo_client.py --base "$BASE" wait-activated edge-eu policy@3 40
python3 scripts/demo_client.py --base "$BASE" wait-activated edge-us policy@3 40
sleep 2
python3 scripts/demo_client.py --base "$BASE" show

echo
echo "== 6/7 现在拉起“长时间离线”的 cn 节点 edge-late-cn =="
echo "       它必须收到 base@1..3 + policy@1..4 的有序链（跳过已撤销的 base@2），"
echo "       而不是直接领取 policy@4 最新快照。"
docker compose --profile late up -d edge-late-cn
python3 scripts/demo_client.py --base "$BASE" wait-activated edge-late-cn policy@4 60
echo "--- edge-late-cn 首次重连日志（注意接收顺序）---"
docker compose logs edge-late-cn | grep -E "ACTIVATED|RECALL|in sync" | head -30 || true
python3 scripts/demo_client.py --base "$BASE" node edge-late-cn

echo
echo "== 7/7 回执防线演示（旧 seq / 乱序空洞 / 错误哈希 / 状态倒退）=="
python3 scripts/demo_client.py --base "$BASE" receipt-attacks

echo
echo "== 最终传播总览 =="
python3 scripts/demo_client.py --base "$BASE" show

cat <<EOF

演示完成。常用命令：
  查看状态:   python3 scripts/demo_client.py show
  看节点日志: docker compose logs -f edge-cn
  清理:       docker compose --profile late down -v
EOF
