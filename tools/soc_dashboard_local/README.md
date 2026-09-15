# Local SOC Dashboard (no cloud required)

Local, self-contained SOC ingest + visualization for the AUTOSAR IDSM toolkit —
the offline alternative to `tools/soc_dashboard_cloud` (Vercel). Runs entirely on
the HIL bench server.

```
eth_probe / eve_bridge ──HTTP──> server.js :9000 ──> InfluxDB :8086 ──> Grafana :3000
```

**Deployment shape**: InfluxDB runs in Docker; Grafana runs **natively** (apt or
tarball) — free CN Docker mirrors 403 the `grafana/grafana` repo, so don't fight it.

## Components

| File | Purpose |
|---|---|
| `server.js` | Zero-dependency Node ingest (receives IDSRM POSTs, decodes context, writes InfluxDB) |
| `docker-compose.yml` | InfluxDB 2.7 only (via daocloud mirror) |
| `../soc_dashboard_cloud/grafana_dashboard.json` | Same dashboard — import into Grafana |

## Quick start

```bash
# 1. Start InfluxDB (Docker)
cd tools/soc_dashboard_local
sudo docker compose up -d
curl http://localhost:8086/health        # expect {"status":"pass"}

# 2. Install Grafana natively — pick ONE:
#    (a) official APT repo:
sudo apt-get install -y apt-transport-https wget gpg
sudo mkdir -p /etc/apt/keyrings
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update && sudo apt-get install -y grafana
sudo systemctl enable --now grafana-server
#    (b) single-binary tarball (no apt):
wget https://dl.grafana.com/oss/release/grafana-10.4.0.linux-amd64.tar.gz
tar xzf grafana-10.4.0.linux-amd64.tar.gz
nohup ./grafana-10.4.0/bin/grafana-server &

curl http://localhost:3000/api/health    # expect {"database":"ok"}

# 3. Start the ingest server (Node >= 16, zero npm deps)
INFLUXDB_TOKEN=idsm-admin-token node server.js
#    (token/org/bucket must match docker-compose.yml)

# 4. Point the probe at it
sudo ./build/eth_probe -i eth1 --soc http://localhost:9000/api/idsm-violations \
    --rules apps/eth_probe/rules/example.rules --cidr apps/eth_probe/rules/chnroutes.txt

# 5. Grafana: http://localhost:3000 (admin/admin) → add InfluxDB data source (Flux):
#      URL = http://localhost:8086   Org = idsm   Token = idsm-admin-token   Bucket = idsm
#    → Dashboards → Import → ../soc_dashboard_cloud/grafana_dashboard.json
```

## Notes

- **Log-only mode**: run `node server.js` without `INFLUXDB_TOKEN` and it just prints
  decoded alerts (useful before InfluxDB is up).
- Health check: `curl http://localhost:9000/health`.
- The compose credentials are lab defaults — change `idsm-admin-pass` /
  `idsm-admin-token` before connecting anything you care about.
- InfluxDB data persists in the docker volume `influx-data`
  (`docker compose down` keeps data; `docker compose down -v` wipes it).
