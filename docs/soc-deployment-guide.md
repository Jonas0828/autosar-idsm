# SOC 部署指南

eth_probe / eve_bridge 的告警经 IDSRM 上报到 SOC 端。两种部署形态：

| 形态 | 目录 | 适用 |
|---|---|---|
| 本地栈（推荐 HIL/内网） | `tools/soc_dashboard_local/` | 实验室台架，无外网依赖 |
| 云端栈 | `tools/soc_dashboard_cloud/` | 有公网，Vercel + InfluxDB Cloud |

## 本地栈（推荐）

```
[probe] ──HTTP──> server.js:9000 ──> InfluxDB:8086 ──> Grafana:3000
```

### 部署步骤

```bash
cd tools/soc_dashboard_local

# 1. InfluxDB (Docker, daocloud 镜像源)
sudo docker compose up -d
curl http://localhost:8086/health    # {"status":"pass"}

# 2. Grafana (原生安装, 不用 Docker — 镜像代理对 grafana/grafana 403)
#    方式A: apt
sudo apt-get install -y apt-transport-https wget gpg
sudo mkdir -p /etc/apt/keyrings
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update && sudo apt-get install -y grafana
sudo systemctl enable --now grafana-server
#    方式B: 单二进制(apt 被墙时)
wget https://dl.grafana.com/oss/release/grafana-10.4.0.linux-amd64.tar.gz
tar xzf grafana-10.4.0.linux-amd64.tar.gz
nohup ./grafana-10.4.0/bin/grafana-server &

curl http://localhost:3000/api/health    # {"database":"ok"}

# 3. SOC ingest server (Node >= 16, 零 npm 依赖)
INFLUXDB_TOKEN=idsm-admin-token nohup node server.js > /tmp/soc-server.log 2>&1 &
curl http://localhost:9000/health    # {"status":"ok",...}
```

### 探针指向

```bash
sudo ./build/eth_probe -i eth1 --soc http://<SOC_IP>:9000/api/idsm-violations ...
```

### Grafana 配置

1. http://<SOC_IP>:3000 → admin/admin
2. Connections → Data sources → InfluxDB:
   - Query language: **Flux**（不是 InfluxQL）
   - URL: `http://localhost:8086`
   - Organization: `idsm`, Token: `idsm-admin-token`, Default Bucket: `idsm`
3. Dashboards → Import → `tools/soc_dashboard_cloud/grafana_dashboard.json`

### 清空告警（重新测试前）

```bash
curl -X POST http://<SOC_IP>:9000/api/clear
```

## 云端栈

`tools/soc_dashboard_cloud/` —— Vercel serverless + InfluxDB Cloud。

**CN 网络限制**：Vercel 需要注册（可能受限）、Docker Hub/grafana 镜像代理对
grafana/grafana 仓库 403。本地栈是内网环境的可靠选择。

## 安全注意事项

- compose/README 里的 token/password 是 lab 默认值（`idsm-admin-token`），
  生产环境**必须改**（docker-compose.yml + server.js 启动环境变量 + Grafana 数据源三处一致）
- `/api/clear` 无鉴权——内网可用，暴露公网前加 token 检查或防火墙限制
- server.js 长期运行建议包 systemd unit（nohup 重启丢失）

## 排错

| 现象 | 排查 |
|---|---|
| 页面没数据 | 1) 探针 `--soc` 端口是 9000 不是 8080  2) server.js `tail /tmp/soc-server.log` 有没有收到  3) InfluxDB 有没有写入（见下） |
| Grafana 数据源测试失败 | Query language 必须是 Flux；token/org/bucket 和 compose 一致 |
| InfluxDB 查数据 | `curl -s "http://localhost:8086/api/v2/query?org=idsm" -H "Authorization: Token idsm-admin-token" -H "Content-Type: application/vnd.flux" -d 'from(bucket:"idsm") |> range(start:-1h) |> filter(fn:(r)=>r._measurement=="idsm_violations") |> limit(n:5)'` |
| server.js 没起来 | `ps aux | grep "node server"`；端口冲突（EADDRINUSE）时 `pkill -f "node server.js"` 再启 |
