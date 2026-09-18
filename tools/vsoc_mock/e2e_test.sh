#!/usr/bin/env bash
# E2E 联调: mock VSOC(broker+服务) + idsm_managerd + host_probe。
# 跑完打印三方日志与 mock 的告警校验结果(PASS/FAIL)。
# 用法: bash tools/vsoc_mock/e2e_test.sh
set -u
cd "$(dirname "$0")/../.."
ROOT=$PWD
MOQ=/home/alientek/work/deps/mosq/root
export LD_LIBRARY_PATH=$MOQ/usr/lib/x86_64-linux-gnu

D=$(mktemp -d /tmp/idsm_e2e.XXXXXX)
echo "[e2e] data dir: $D"
echo "/tmp/idsm_watched.txt" > /tmp/myfiles.txt
echo init > /tmp/idsm_watched.txt

python3 tools/vsoc_mock/mock_vsoc.py --expect-alerts 20 --alert-min 1 \
    > "$D/mock.log" 2>&1 &
MOCK_PID=$!

./build/linux/idsm_managerd/idsm_managerd --no-tls \
    --broker 127.0.0.1:18883 \
    --device-id caic_t99_LXXXXXXX202000001 \
    --vin LXXXXXXX202000001 \
    --register \
    --ecu-code 0x01 \
    --data-dir "$D" --rules-dir "$D/rules" --seed-dir "$D/seed" \
    --socket "$D/host.sock" > "$D/managerd.log" 2>&1 &
MGR_PID=$!

./build/host_probe --baseline-exec apps/host_probe/baseline/example_exec.txt \
    --baseline-files /tmp/myfiles.txt \
    --baseline-mods apps/host_probe/baseline/example_mods.txt \
    --sink "$D/host.sock" > "$D/probe.log" 2>&1 &
PROBE_PID=$!

sleep 4
xxd --help > /dev/null 2>&1          # DT_UNKNOWN_EXEC 类告警
echo tampered >> /tmp/idsm_watched.txt  # DT_SENSITIVE_FILE_MOD 类告警

for _ in $(seq 1 40); do
  kill -0 $MOCK_PID 2>/dev/null || break
  sleep 1
done
kill $MGR_PID $PROBE_PID $MOCK_PID 2>/dev/null
wait $MOCK_PID 2>/dev/null
MOCK_RC=$?

echo "==================== mock (rc=$MOCK_RC) ===================="
tail -40 "$D/mock.log"
echo "==================== managerd ===================="
tail -40 "$D/managerd.log"
echo "==================== probe ===================="
tail -10 "$D/probe.log"
echo "[e2e] credentials: $(test -f "$D/credentials.json" && echo SAVED || echo MISSING)"
echo "[e2e] logs kept in $D"
