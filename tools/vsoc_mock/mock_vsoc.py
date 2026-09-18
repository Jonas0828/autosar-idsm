#!/usr/bin/env python3
"""mock_vsoc -- VSOC 云端 mock,用于车端按《VSOC 设备接入详细设计 v1.0》开发联调。

单进程内含三件套:
  1. amqtt MQTT broker(默认 127.0.0.1:18883, 实验室无认证)
  2. 注册服务 mock: 应答 sys/init/request -> clientId+token; sys/cert/request
     返回 1004(mock 不接管 PKI)
  3. 规则签名服务 mock(python 参考实现): Ed25519 签名 + 设计文档 10.1
     canonical 字节序列,向单车 topic 发布签名规则包(retain)

canon 实现是本仓库 C++ 侧(linux/idsm_managerd)的互操作基准,
两侧必须逐字节一致。

用法:
  # 起 broker + 注册服务,并等待/校验告警上报:
  python3 tools/vsoc_mock/mock_vsoc.py --expect-alerts 10 --alert-min 1

  # 另开窗口对某设备下发签名规则包:
  python3 tools/vsoc_mock/mock_vsoc.py --sign-rule \
      --device caic_t99_LXXXXXXX202000001 --seq 1 --version v8 \
      --rule 'alert tcp any any -> any 3389 (msg:"RDP"; sid:10001;)'
"""
import argparse
import asyncio
import base64
import hashlib
import json
import secrets
import signal
import sys
import threading
import time

from amqtt.broker import Broker

from cryptography.hazmat.primitives import serialization

BROKER_HOST = "127.0.0.1"
BROKER_PORT = 18883


# ──────────────────────── canonical 字节序列(v1.0 §10.1) ────────────────────────

def canonical_bytes(seq, tenant, version, rollback, target, upgrade_type,
                    payload_lines, issued_at, expires_at):
    """payload_lines: 已按 ASCII 升序排好序的 payload 行列表(不含换行)。"""
    lines = [
        f"seq={seq}",
        f"tenant={tenant}",
        f"version={version}",
        f"rollback={1 if rollback else 0}",
        f"target_ecu={target['ecu']}",
        f"target_node={target['nodeType']}",
        f"target_vmodel={target['vmodel']}",
        f"issued_at={issued_at}",
        f"expires_at={expires_at}",
        f"upgrade_type={upgrade_type}",
    ] + sorted(payload_lines)
    return ("\n".join(lines) + "\n").encode("utf-8")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def sign_rule_bundle(key, *, seq, tenant, version, rollback, target,
                     upgrade_type, rules=None, download_uri=None,
                     validity_s=7 * 24 * 3600):
    """构造签名规则包(设计文档 10.2),返回可发布的 dict。"""
    now = int(time.time())
    payload_lines = []
    if upgrade_type == 1:
        for i, r in enumerate(rules or []):
            payload_lines.append(f"rule:{10000 + i}:{b64(r.encode())}")
    else:
        payload_lines.append(f"uri:{download_uri}")
    canonical = canonical_bytes(seq, tenant, version, rollback, target,
                                upgrade_type, payload_lines, now,
                                now + validity_s)
    sig = key.sign(canonical)
    bundle = {
        "msg_type": "rule_update",
        "protocol_version": "1.0",
        "timestamp": int(time.time() * 1000),
        "manufacturer": tenant,
        "seq": seq,
        "version": version,
        "rollback": rollback,
        "target": target,
        "upgrade_type": upgrade_type,
        "issued_at": now,
        "expires_at": now + validity_s,
        "sig_alg": "Ed25519",
        "pubkey_id": hashlib.sha256(key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)).hexdigest()[:16],
        "signature": b64(sig),
    }
    if upgrade_type == 1:
        bundle["rules"] = rules or []
    else:
        bundle["download_uri"] = download_uri
    return bundle, canonical


# ──────────────────────── broker + 服务 ────────────────────────

BROKER_CONFIG = {
    "listeners": {"default": {"type": "tcp",
                              "bind": f"{BROKER_HOST}:{BROKER_PORT}",
                              "max_connections": 64}},
    "sys_interval": 0,
    "auth": {"allow-anonymous": True},
    # amqtt 0.10.1:enabled:False 会回退为调用全部 topic 检查插件,
    # 内置 ACL 插件因缺 "acl" 配置抛 KeyError -> SUBACK 0x80 拒绝订阅。
    # enabled:True + plugins:[] 是官方文档化的"不启用任何检查插件"写法。
    "topic-check": {"enabled": True, "plugins": []},
}


def start_paho_services(expect_alerts, alert_min, stop_evt):
    """注册服务 mock + 告警接收校验器,跑在独立线程(paho loop)。"""
    import paho.mqtt.client as mqtt

    stats = {"alerts": 0, "bad": []}

    def on_connect(client, _ud, _flags, rc, _props=None):
        if rc != 0:
            print(f"[mock] connect rc={rc}", flush=True)
            return
        print("[mock] services online", flush=True)
        client.subscribe("oc/devices/+/sys/init/request/+")
        client.subscribe("oc/devices/+/sys/cert/request/+")
        if expect_alerts:
            for seg in ("host", "eth", "can"):
                client.subscribe(f"oc/devices/+/sys/idps/{seg}/log")

    def on_message(client, _ud, msg):
        topic = msg.topic
        try:
            payload = json.loads(msg.payload)
        except Exception:
            stats["bad"].append((topic, "not json"))
            return
        parts = topic.split("/")
        did = parts[2] if len(parts) > 2 else "?"
        if "/sys/init/request/" in topic:
            rid = parts[-1].split("=", 1)[-1]
            client_id = f"vehicle_{payload['content']['modelId']}_{secrets.token_hex(8)}"
            resp = {
                "rc": 0, "rn": "register_response", "request_id": rid,
                "timestamp": int(time.time() * 1000),
                "paras": {"msg": "注册成功(mock)", "client_id": client_id,
                          "token": secrets.token_urlsafe(24),
                          "token_expire": int(time.time()) + 7200},
            }
            client.publish(f"oc/devices/{did}/sys/init/response/rid={rid}",
                           json.dumps(resp), qos=1)
            print(f"[mock] init {did} -> clientId issued", flush=True)
        elif "/sys/cert/request/" in topic:
            rid = parts[-1].split("=", 1)[-1]
            resp = {"rc": 1004, "rn": "cert_apply_response", "request_id": rid,
                    "timestamp": int(time.time() * 1000),
                    "paras": {"msg": "mock 不接管 PKI"}}
            client.publish(f"oc/devices/{did}/sys/cert/response/rid={rid}",
                           json.dumps(resp), qos=1)
        elif "/sys/idps/" in topic and topic.endswith("/log"):
            seg = parts[-2]
            ok, why = validate_alert_envelope(payload, seg)
            if ok:
                stats["alerts"] += len(payload.get("content", []))
                print(f"[mock] alert {seg} x{len(payload.get('content', []))} "
                      f"from {did} ok", flush=True)
            else:
                stats["bad"].append((topic, why))
                print(f"[mock] BAD alert envelope: {why}", flush=True)

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    c.on_connect = on_connect
    c.on_message = on_message
    for attempt in range(30):          # 等 broker 就绪
        try:
            c.connect(BROKER_HOST, BROKER_PORT, 60)
            break
        except Exception:
            time.sleep(1)
    else:
        print("[mock] broker unreachable", flush=True)
        return 1
    c.loop_start()
    if expect_alerts:
        stop_evt.wait(expect_alerts)
        c.loop_stop()
        print(f"[mock] expect window end: alerts={stats['alerts']} "
              f"bad={len(stats['bad'])}", flush=True)
        for t, why in stats["bad"]:
            print(f"  BAD {t}: {why}", flush=True)
        rc = 0 if stats["alerts"] >= alert_min and not stats["bad"] else 1
        print(f"[mock] RESULT {'PASS' if rc == 0 else 'FAIL'}", flush=True)
        return rc
    while not stop_evt.is_set():
        time.sleep(0.5)
    c.loop_stop()
    return 0


def validate_alert_envelope(env, seg):
    """按设计文档 6.1/9.1 做轻量校验。"""
    if env.get("msg_type") != f"alert_{seg}":
        return False, f"msg_type={env.get('msg_type')}"
    if env.get("protocol_version") != "1.0":
        return False, "protocol_version"
    if not isinstance(env.get("timestamp"), int):
        return False, "timestamp"
    content = env.get("content")
    if not isinstance(content, list) or not content:
        return False, "content"
    for e in content:
        for k in ("eventId", "eventType", "severity", "timestamp", "ecuCode",
                  "nodeType", "ruleVersion", "replay", "raw"):
            if k not in e:
                return False, f"missing {k}"
        if e["nodeType"].lower() != {"host": "hidps", "eth": "nidps",
                                     "can": "cids"}[seg]:
            return False, f"nodeType={e['nodeType']}"
        if e["severity"] not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            return False, f"severity={e['severity']}"
    return True, ""


async def run_broker(stop_evt):
    broker = Broker(BROKER_CONFIG)
    await broker.start()
    print(f"[mock] broker listening {BROKER_HOST}:{BROKER_PORT}", flush=True)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, stop_evt.wait)
    await broker.shutdown()


def main():
    ap = argparse.ArgumentParser(description="mock VSOC (broker + reg service + rule signer)")
    ap.add_argument("--expect-alerts", type=int, default=0,
                    help="运行 N 秒等待告警并校验信封,结束打印 PASS/FAIL")
    ap.add_argument("--alert-min", type=int, default=1)
    ap.add_argument("--sign-rule", action="store_true",
                    help="签名并向 --device 发布规则包后退出(需 broker 已运行)")
    ap.add_argument("--device", default="caic_t99_LXXXXXXX202000001")
    ap.add_argument("--tenant", default="caic")
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--version", default="v8")
    ap.add_argument("--rollback", action="store_true")
    ap.add_argument("--rule", action="append", default=[])
    ap.add_argument("--ecu", default="all")
    ap.add_argument("--node-type", default="all")
    ap.add_argument("--vmodel", default="all")
    ap.add_argument("--keyfile", default="/tmp/vsoc_mock_ed25519.pem")
    args = ap.parse_args()

    if args.sign_rule:
        return do_sign_rule(args)

    stop_evt = threading.Event()
    def sig(_s, _f):
        stop_evt.set()
    signal.signal(signal.SIGTERM, sig)
    signal.signal(signal.SIGINT, sig)

    result = {}

    def run_services():
        result["rc"] = start_paho_services(args.expect_alerts,
                                           args.alert_min, stop_evt)
        stop_evt.set()

    st = threading.Thread(target=run_services, daemon=True)
    st.start()
    asyncio.run(run_broker(stop_evt))
    st.join(timeout=5)
    return result.get("rc", 0)


def do_sign_rule(args):
    import paho.mqtt.client as mqtt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    try:
        key = serialization.load_pem_private_key(
            open(args.keyfile, "rb").read(), password=None)
        print(f"[mock] loaded key {args.keyfile}")
    except Exception:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        open(args.keyfile, "wb").write(pem)
        print(f"[mock] generated key -> {args.keyfile}")
        print(f"[mock] SPKI b64(pubkey)="
              f"{b64(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))}")

    if not args.rule:
        args.rule = ['alert tcp any any -> any 3389 (msg:"RDP"; sid:10001;)']
    target = {"ecu": args.ecu, "nodeType": args.node_type, "vmodel": args.vmodel}
    bundle, canonical = sign_rule_bundle(
        key, seq=args.seq, tenant=args.tenant, version=args.version,
        rollback=args.rollback, target=target, upgrade_type=1, rules=args.rule)

    done = threading.Event()
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

    def on_connect(client, _ud, _flags, rc, _props=None):
        topic = f"oc/devices/{args.device}/sys/idps/rule/update"
        client.publish(topic, json.dumps(bundle), qos=1, retain=True)
        print(f"[mock] signed rule v{args.version} seq={args.seq} -> {topic}")
        done.set()

    c.on_connect = on_connect
    c.connect(BROKER_HOST, BROKER_PORT, 60)
    c.loop_start()
    done.wait(10)
    c.loop_stop()
    print("[mock] canonical preview:")
    print(canonical.decode(), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
