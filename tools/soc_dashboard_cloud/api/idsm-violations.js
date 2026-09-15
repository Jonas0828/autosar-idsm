const VALID_SEVERITIES = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

// R24-11 schema sent by IDSRM (src/IdsRm_Manager.cpp buildJsonPayload)
const REQUIRED_FIELDS = [
  "ids_message",
  "idsm_instance_id",
  "sensor_instance_id",
  "event_id",
  "count",
  "severity",
  "context_data_version",
  "payload",
  "payload_len",
];

// detector_type → name (apps/eth_probe/alert.h)
const DETECTOR_NAMES = {
  1: "PORT_SCAN", 2: "RATE_FLOOD", 3: "FLAG_ANOMALY", 4: "RULE_HIT",
  5: "DOIP", 6: "SOME_IP", 7: "REASSEMBLY", 8: "CROSS_BORDER",
  9: "TLS", 10: "HTTP", 11: "DNS", 12: "ARP_SPOOF", 100: "SURICATA",
};
const PROTO_NAMES = { 1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6" };

function ipStr(b) {
  // IPv4 occupies first 4 bytes (rest zero); else IPv6
  const isV4 = b.slice(4).every((x) => x === 0);
  if (isV4) return b.slice(0, 4).join(".");
  const groups = [];
  for (let i = 0; i < 16; i += 2)
    groups.push(((b[i] << 8) | b[i + 1]).toString(16));
  return groups.join(":");
}

// Decode 46-byte context layout v1 → human summary + structured fields.
// Returns null for other layouts (caller stores raw payload only).
function decodeContext(payloadHex) {
  let raw;
  try {
    raw = Buffer.from(payloadHex, "hex");
  } catch {
    return null;
  }
  if (raw.length !== 46) return null;
  const detType = raw[0];
  const proto = raw[1];
  const sport = raw.readUInt16BE(2);
  const dport = raw.readUInt16BE(4);
  const srcIp = ipStr([...raw.slice(6, 22)]);
  const dstIp = ipStr([...raw.slice(22, 38)]);
  const count = raw.readUInt32BE(38);
  const aux = raw.readUInt32BE(42);
  const det = DETECTOR_NAMES[detType] || `TYPE_${detType}`;
  const protoS = PROTO_NAMES[proto] || String(proto);
  return {
    detector: det,
    detector_type: detType,
    proto: protoS,
    src_ip: srcIp,
    src_port: sport,
    dst_ip: dstIp,
    dst_port: dport,
    aux,
    count,
    summary: `${det} ${protoS} ${srcIp}:${sport} -> ${dstIp}:${dport} aux=0x${aux
      .toString(16)
      .toUpperCase()} x${count}`,
  };
}

function escapeLpString(s) {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}
function escapeLpTag(s) {
  return s.replace(/[ ,=]/g, (c) => "\\" + c);
}

function toLineProtocol(event, decoded, receivedAtNs) {
  // Tags: low-cardinality indexed fields (queryable dimensions)
  const tags = [
    `severity=${escapeLpTag(event.severity)}`,
    `idsm_instance=${event.idsm_instance_id}`,
    `sensor_instance=${event.sensor_instance_id}`,
    `detector=${escapeLpTag(decoded ? decoded.detector : "UNKNOWN")}`,
  ].join(",");

  // Fields: values (numerics as ints, strings quoted)
  const fields = [
    `event_id=${event.event_id}i`,
    `count=${event.count}i`,
    `context_data_version=${event.context_data_version}i`,
    `payload_len=${event.payload_len}i`,
    `payload="${escapeLpString(event.payload)}"`,
    `ids_message="${escapeLpString(event.ids_message)}"`,
  ];
  if (decoded) {
    fields.push(
      `detector_type=${decoded.detector_type}i`,
      `aux=${decoded.aux}i`,
      `src_ip="${escapeLpString(decoded.src_ip)}"`,
      `dst_ip="${escapeLpString(decoded.dst_ip)}"`,
      `src_port=${decoded.src_port}i`,
      `dst_port=${decoded.dst_port}i`,
      `proto="${escapeLpString(decoded.proto)}"`,
      `summary="${escapeLpString(decoded.summary)}"`
    );
  }

  return `idsm_violations,${tags} ${fields.join(",")} ${receivedAtNs}`;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  let body;
  try {
    body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: "Invalid JSON" });
  }

  for (const field of REQUIRED_FIELDS) {
    if (body[field] === undefined || body[field] === null) {
      return res.status(400).json({ error: `Missing field: ${field}` });
    }
  }
  if (!VALID_SEVERITIES.has(body.severity)) {
    return res.status(400).json({ error: `Invalid severity: ${body.severity}` });
  }
  if (
    typeof body.idsm_instance_id !== "number" ||
    typeof body.sensor_instance_id !== "number" ||
    typeof body.event_id !== "number" ||
    typeof body.count !== "number" ||
    typeof body.context_data_version !== "number" ||
    typeof body.payload_len !== "number" ||
    typeof body.payload !== "string" ||
    typeof body.ids_message !== "string"
  ) {
    return res.status(400).json({ error: "Invalid field types" });
  }

  const { INFLUXDB_URL, INFLUXDB_TOKEN, INFLUXDB_ORG, INFLUXDB_BUCKET } =
    process.env;
  if (!INFLUXDB_URL || !INFLUXDB_TOKEN || !INFLUXDB_ORG || !INFLUXDB_BUCKET) {
    console.error("Missing InfluxDB environment variables");
    return res.status(500).json({ error: "Server misconfigured" });
  }

  const decoded = decodeContext(body.payload);
  const receivedAtNs = BigInt(Date.now()) * 1_000_000n;
  const lineProtocol = toLineProtocol(body, decoded, receivedAtNs);

  const baseUrl = INFLUXDB_URL.replace(/\/+$/, "");
  const writeUrl = `${baseUrl}/api/v2/write?org=${encodeURIComponent(
    INFLUXDB_ORG
  )}&bucket=${encodeURIComponent(INFLUXDB_BUCKET)}&precision=ns`;

  let influxRes;
  try {
    influxRes = await fetch(writeUrl, {
      method: "POST",
      headers: {
        Authorization: `Token ${INFLUXDB_TOKEN}`,
        "Content-Type": "text/plain; charset=utf-8",
      },
      body: lineProtocol,
    });
  } catch (err) {
    console.error("InfluxDB write failed:", err.message);
    return res.status(502).json({ error: "Failed to reach InfluxDB" });
  }

  if (influxRes.status !== 204) {
    const text = await influxRes.text();
    console.error("InfluxDB returned non-204:", influxRes.status, text);
    return res.status(502).json({
      error: "InfluxDB write error",
      status: influxRes.status,
      detail: text,
    });
  }

  return res
    .status(200)
    .json({ status: "ok", decoded: decoded ? decoded.summary : null });
}
