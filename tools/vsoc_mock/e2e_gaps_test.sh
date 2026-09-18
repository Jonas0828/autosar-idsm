# E2E 缺口全链路: mock VSOC + idsm_managerd + host_probe。
# 覆盖: 规则/配置下发(Applied)、upgrade_type=2 显式拒绝(事件闭环)、
# 日志快照分包 + negative-ack 补片、证书续期(归 PKI 1004 退避)、
# nodeStatus 接 UDS 真实连接状态(杀探针 -> 离线 -> 重启 -> 在线)。
# 用法: bash tools/vsoc_mock/e2e_gaps_test.sh
set -u
cd "$(dirname "$0")/../.."
ROOT=$PWD
MOQ=/home/alientek/work/deps/mosq/root
export LD_LIBRARY_PATH=$MOQ/usr/lib/x86_64-linux-gnu

D=$(mktemp -d /tmp/idsm_gaps.XXXXXX)
echo "[e2e] data dir: $D"
DEVICE=caic_t99_LXXXXXXX202000001

echo "/tmp/idsm_watched.txt" > /tmp/myfiles.txt
echo init > /tmp/idsm_watched.txt

# 规则/配置签名 key(mock 与 managerd 共用公钥)
openssl genpkey -algorithm ed25519 -outform PEM -out "$D/signkey.pem" 2>/dev/null
PUBKEY_B64=$(openssl pkey -in "$D/signkey.pem" -pubout -outform DER 2>/dev/null | base64 -w0)

# 业务证书: 总有效期 25 天, 剩余 5 天 < 1/3 -> 触发续期(3.3)
python3 - "$D" << 'PY'
import datetime
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

d = sys.argv[1]
key = ed25519.Ed25519PrivateKey.generate()
with open(f"{d}/device.key", "wb") as f:
    f.write(key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))
now = datetime.datetime.utcnow()
builder = (x509.CertificateBuilder()
           .subject_name(x509.Name([x509.NameAttribute(
               NameOID.COMMON_NAME, "caic_t99_TEST")]))
           .issuer_name(x509.Name([x509.NameAttribute(
               NameOID.COMMON_NAME, "caic_t99_TEST")]))
           .public_key(key.public_key())
           .serial_number(1))
try:
    builder = builder.not_valid_before_utc(now - datetime.timedelta(days=20))
    builder = builder.not_valid_after_utc(now + datetime.timedelta(days=5))
except AttributeError:
    builder = builder.not_valid_before(now - datetime.timedelta(days=20))
    builder = builder.not_valid_after(now + datetime.timedelta(days=5))
try:
    cert = builder.sign(key, None)   # Ed25519: algorithm 必须 None
except TypeError:   # cryptography 2.x: backend 必传
    from cryptography.hazmat.backends import default_backend
    cert = builder.sign(key, None, default_backend())
with open(f"{d}/device.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
PY

# 300KB 取证文件(> 256KB 必须分包, 11 章)
python3 -c "
import sys
with open('$D/attack.pcap', 'wb') as f:
    f.write(bytes((i * 31 + 7) & 0xff for i in range(300000)))
"

python3 tools/vsoc_mock/mock_vsoc.py \
    --expect-alerts 45 --alert-min 1 \
    --expect-events 1 --expect-snapshot 1 --drop-chunk 1 \
    > "$D/mock.log" 2>&1 &
MOCK_PID=$!

./build/linux/idsm_managerd/idsm_managerd --no-tls \
    --broker 127.0.0.1:18883 \
    --device-id "$DEVICE" \
    --vin LXXXXXXX202000001 \
    --register \
    --ecu-code 0x01 \
    --data-dir "$D" --rules-dir "$D/rules" --seed-dir "$D/seed" \
    --config-dir "$D/config" --snapshot-dir "$D/snapshots" \
    --socket "$D/host.sock" \
    --pubkey-b64 "$PUBKEY_B64" \
    --reload-cmd "true" \
    --renew-cert --cert-file "$D/device.crt" --key-file "$D/device.key" \
    --device-serial SN0001 \
    > "$D/managerd.log" 2>&1 &
MGR_PID=$!

start_probe() {
    ./build/host_probe --baseline-exec apps/host_probe/baseline/example_exec.txt \
        --baseline-files /tmp/myfiles.txt \
        --baseline-mods apps/host_probe/baseline/example_mods.txt \
        --sink "$D/host.sock" > "$D/probe.log" 2>&1 &
    PROBE_PID=$!
}
start_probe

sleep 5
xxd --help > /dev/null 2>&1          # DT_UNKNOWN_EXEC 类告警
echo tampered >> /tmp/idsm_watched.txt  # DT_SENSITIVE_FILE_MOD 类告警

# nodeStatus 真实连接状态: 杀探针 -> HIDPS 离线(立即增量上报), 重启 -> 在线
kill "$PROBE_PID" 2>/dev/null
wait "$PROBE_PID" 2>/dev/null
sleep 3
start_probe
sleep 3

# 日志快照: 探针经 UDS 命令请求上传(分包 + nack 补片闭环)
python3 - "$D" << 'PY'
import json
import socket
import sys

d = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(f"{d}/host.sock")
s.sendall((json.dumps({
    "cmd": "log_upload",
    "file": f"{d}/attack.pcap",
    "event_id": "caic_t99_LXXXXXXX202000001-HIDPS-deadbeef",
    "remark": "端口扫描取证",
}) + "\n").encode())
s.close()
PY

# 规则下发(内联) -> Applied(retain 覆盖语义: 每次下发间隔 3s, 先消费再发)
python3 tools/vsoc_mock/mock_vsoc.py --sign-rule --keyfile "$D/signkey.pem" \
    --device "$DEVICE" --seq 1 --version v8 \
    --rule 'alert tcp any any -> any 3389 (msg:"RDP"; sid:10001;)'
sleep 3
# 配置下发(黑白名单) -> Applied
python3 tools/vsoc_mock/mock_vsoc.py --sign-config --keyfile "$D/signkey.pem" \
    --device "$DEVICE" --seq 1 --version c1 \
    --item '{"config_name":"process_w_list","config_value":["/usr/sbin/sshd"],"config_version":"c1"}'
sleep 3
# URL 规则包(upgrade_type=2) -> 显式拒绝 + 事件闭环
python3 tools/vsoc_mock/mock_vsoc.py --sign-rule --keyfile "$D/signkey.pem" \
    --device "$DEVICE" --seq 2 --version v9 --upgrade-type 2

for _ in $(seq 1 60); do
  kill -0 $MOCK_PID 2>/dev/null || break
  sleep 1
done
kill $MGR_PID $PROBE_PID $MOCK_PID 2>/dev/null
wait $MOCK_PID 2>/dev/null
MOCK_RC=$?

check() {  # check <描述> <文件> <模式>
    if grep -q "$3" "$2"; then
        echo "[e2e] PASS: $1"
    else
        echo "[e2e] FAIL: $1 (pattern: $3)"
        MOCK_RC=1
    fi
}

echo "==================== mock (rc=$MOCK_RC) ===================="
tail -50 "$D/mock.log"
echo "==================== managerd ===================="
tail -60 "$D/managerd.log"

check "规则下发 Applied"          "$D/managerd.log" "rules activated"
check "配置下发 Applied"          "$D/managerd.log" "config applied"
check "upgrade_type=2 显式拒绝"   "$D/managerd.log" "upgrade_type=2"
check "拒绝事件上报闭环"          "$D/mock.log"     "event_up RULE_REJECT"
check "规则防回滚(replay 拒绝)"   "$D/managerd.log" "seq rollback rejected"
check "快照补片闭环"              "$D/mock.log"     "nack missing"
check "快照整体校验通过"          "$D/mock.log"     "SNAPSHOT OK"
check "证书续期申请"              "$D/managerd.log" "cert renewal request"
check "证书归 PKI(1004 退避)"     "$D/managerd.log" "cert apply rc=1004"
check "nodeStatus 探针离线"       "$D/mock.log"     "HIDPS:off"
check "nodeStatus 探针重连在线"   "$D/mock.log"     "HIDPS:on"
check "注册成功"                  "$D/managerd.log" "registered: client_id"
echo "[e2e] credentials: $(test -f "$D/credentials.json" && echo SAVED || echo MISSING)"
echo "[e2e] mock RESULT: $(grep -o 'RESULT PASS\|RESULT FAIL' "$D/mock.log" | tail -1)"
echo "[e2e] logs kept in $D"
exit $MOCK_RC
