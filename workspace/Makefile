.PHONY: help up down logs rebuild demo test test-unit test-e2e clean ps

help:  ## 显示可用目标
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-12s %s\n", $$1, $$2}'

up:  ## 构建并启动控制面 + cn/eu/us 三个边缘节点
	docker compose up -d --build controller edge-cn edge-eu edge-us

down:  ## 停止（含晚到节点 profile）并删除数据卷
	docker compose --profile late down -v

logs:  ## 跟踪所有服务日志
	docker compose logs -f

ps:  ## 查看服务状态
	docker compose --profile late ps

demo:  ## 一键完整演示（发布/依赖/撤销/覆盖/离线重连/回执攻击）
	./demo.sh

test-unit:  ## 纯逻辑 + 服务层单测（无需容器，标准库）
	python3 -m unittest discover -s tests -v

test-e2e:  ## 起真实 HTTP 控制面 + 代理子进程的端到端测试
	python3 -m unittest tests.test_e2e -v

test: test-unit test-e2e  ## 全部测试

rebuild:  ## 强制重建镜像
	docker compose build --no-cache

clean: down
	docker image rm policy-propagator:latest 2>/dev/null || true
