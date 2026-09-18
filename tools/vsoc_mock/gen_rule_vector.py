#!/usr/bin/env python3
"""生成 C++ 互操作测试向量: python 侧 Ed25519 签名, C++ 侧验签。

由 ctest fixture 在跑 test_managerd 前现场调用, 时间戳随生成时刻走,
向量永不过期。签名 key 为固定种子的测试 key(非 secret)。

用法: gen_rule_vector.py OUT.json
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mock_vsoc import sign_rule_bundle, sign_config_bundle  # noqa: E402

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

# 固定种子的测试 key(公开, 仅测试用)
_SEED = bytes(range(32))


def main():
    out_path = sys.argv[1]
    key = Ed25519PrivateKey.from_private_bytes(_SEED)
    target = {"ecu": "0x01", "nodeType": "HIDPS", "vmodel": "t99"}
    bundle, canonical = sign_rule_bundle(
        key, seq=42, tenant="caic", version="v8", rollback=False,
        target=target, upgrade_type=1,
        rules=['alert tcp any any -> any 3389 (msg:"RDP"; sid:10001;)'])
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    vec = {
        "pubkey_spki_b64": base64.b64encode(pub_der).decode(),
        "bundle": bundle,
        "canonical": canonical.decode("utf-8"),
    }
    # 配置包互操作向量(10.3): 与规则包共用签名 key/序号种子无关
    citems = [("app_w_list", ["/usr/sbin/sshd", "/usr/bin/crond"], "c1"),
              ("fw_ip_b_list", ["10.0.0.66"], "c2")]
    cbundle, ccanonical = sign_config_bundle(
        key, seq=7, tenant="caic", version="c1", rollback=False,
        target=target, config_type=1, items=citems)
    vec["config_bundle"] = cbundle
    vec["config_canonical"] = ccanonical.decode("utf-8")
    with open(out_path, "w") as f:
        json.dump(vec, f, indent=1)
    print(f"[vector] {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
