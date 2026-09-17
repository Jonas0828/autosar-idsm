#!/usr/bin/env node
/*
 * server.js — local SOC ingest for the AUTOSAR IDSM toolkit.
 *
 * Receives IDSRM POSTs (R24-11 schema), decodes the 46-byte context v1,
 * and writes to a local InfluxDB 2.x instance. Zero npm dependencies —
 * Node's built-in http/https only. Node >= 16.
 *
 * Env:
 *   LISTEN_PORT      (default 9000)
 *   INFLUXDB_URL     (default http://localhost:8086)
 *   INFLUXDB_TOKEN   (required)
 *   INFLUXDB_ORG     (default idsm)
 *   INFLUXDB_BUCKET  (default idsm)
 */
"use strict";

const http = require("http");

const LISTEN_PORT = parseInt(process.env.LISTEN_PORT || "9000", 10);
const INFLUX_URL = (process.env.INFLUXDB_URL || "http://localhost:8086")
  .replace(/\/+$/, "");
const INFLUX_TOKEN = process.env.INFLUXDB_TOKEN || "";
const INFLUX_ORG = process.env.INFLUXDB_ORG || "idsm";
const INFLUX_BUCKET = process.env.INFLUXDB_BUCKET || "idsm";

const VALID_SEVERITIES = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

// detector_type → name (apps/eth_probe/alert.h)
const DETECTOR_NAMES = {
  1: "PORT_SCAN", 2: "RATE_FLOOD", 3: "FLAG_ANOMALY", 4: "RULE_HIT",
  5: "DOIP", 6: "SOME_IP", 7: "REASSEMBLY", 8: "CROSS_BORDER",
  9: "TLS", 10: "HTTP", 11: "DNS", 12: "ARP_SPOOF", 100: "SURICATA",
};
// ext event ID → name for host_probe (apps/host_probe/alert.h, 0x8021-0x802A)
const HOST_DETECTOR_NAMES = {
  0x8021: "HOST_UNKNOWN_EXEC", 0x8022: "HOST_PRIV_ESC",
  0x8023: "HOST_FORK_FLOOD", 0x8024: "HOST_REV_SHELL",
  0x8025: "HOST_FILE_MOD", 0x8026: "HOST_NEW_SETUID",
  0x8027: "HOST_KMOD_LOAD", 0x8028: "HOST_ZOMBIE_STORM",
  0x8029: "HOST_RES_EXHAUST", 0x802a: "HOST_ROOT_SHELL",
};
const PROTO_NAMES = { 1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6" };

function ipStr(b) {
  const isV4 = b.slice(4).every((x) => x === 0);
  if (isV4) return b.slice(0, 4).join(".");
  const groups = [];
  for (let i = 0; i < 16; i += 2)
    groups.push(((b[i] << 8) | b[i + 1]).toString(16));
  return groups.join(":");
}

// Decode context layout v1 → human summary + structured fields.
// Two layouts: 46-byte eth (ext 0x8003) and 32-byte host (ext 0x8021+).
// Returns null for other layouts (caller stores raw payload only).
function decodeContext(payloadHex, eventId) {
  let raw;
  try {
    raw = Buffer.from(payloadHex, "hex");
  } catch {
    return null;
  }
  if (raw.length === 46) return decodeEthContext(raw);
  if (raw.length === 32) return decodeHostContext(raw, eventId);
  return null;
}

function decodeEthContext(raw) {
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

// host context layout v1 (32B, big-endian):
//   [0] detector_type [1] flags | [2..5] pid | [6..9] uid (file mode)
//   [10..13] count | [14..17] aux | [18..29] name[12]
function decodeHostContext(raw, eventId) {
  const detType = raw[0];
  const flags = raw[1];
  const pid = raw.readUInt32BE(2);
  const uid = raw.readUInt32BE(6);
  const count = raw.readUInt32BE(10);
  const aux = raw.readUInt32BE(14);
  const proc = raw.slice(18, 30).toString("utf8").split("\0")[0];
  const det = HOST_DETECTOR_NAMES[eventId] || `HOST_TYPE_${detType}`;
  return {
    detector: det,
    detector_type: detType,
    flags,
    host_pid: pid,
    uid,
    proc,
    aux,
    count,
    summary: `${det} proc=${proc || "?"} pid=${pid} uid=${uid} aux=0x${aux
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
  const tags = [
    `severity=${escapeLpTag(event.severity)}`,
    `idsm_instance=${event.idsm_instance_id}`,
    `sensor_instance=${event.sensor_instance_id}`,
    `detector=${escapeLpTag(decoded ? decoded.detector : "UNKNOWN")}`,
  ].join(",");

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
      `summary="${escapeLpString(decoded.summary)}"`
    );
    if (decoded.src_ip !== undefined) {
      fields.push(
        `src_ip="${escapeLpString(decoded.src_ip)}"`,
        `dst_ip="${escapeLpString(decoded.dst_ip)}"`,
        `src_port=${decoded.src_port}i`,
        `dst_port=${decoded.dst_port}i`,
        `proto="${escapeLpString(decoded.proto)}"`
      );
    }
    if (decoded.proc !== undefined) {
      fields.push(
        `proc="${escapeLpString(decoded.proc)}"`,
        `host_pid=${decoded.host_pid}i`
      );
    }
  }
  return `idsm_violations,${tags} ${fields.join(",")} ${receivedAtNs}`;
}

function writeToInflux(line) {
  return new Promise((resolve, reject) => {
    const url = new URL(
      `${INFLUX_URL}/api/v2/write?org=${encodeURIComponent(INFLUX_ORG)}` +
        `&bucket=${encodeURIComponent(INFLUX_BUCKET)}&precision=ns`
    );
    const mod = url.protocol === "https:" ? require("https") : http;
    const req = mod.request(
      {
        method: "POST",
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        headers: {
          Authorization: `Token ${INFLUX_TOKEN}`,
          "Content-Type": "text/plain; charset=utf-8",
          "Content-Length": Buffer.byteLength(line),
        },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      }
    );
    req.on("error", reject);
    req.write(line);
    req.end();
  });
}

/* DELETE all points in the bucket (InfluxDB delete API: predicate-less
   deletes everything in the range). Returns InfluxDB's status code. */
function clearInflux() {
  return new Promise((resolve, reject) => {
    const url = new URL(`${INFLUX_URL}/api/v2/delete?org=${encodeURIComponent(INFLUX_ORG)}` +
      `&bucket=${encodeURIComponent(INFLUX_BUCKET)}`);
    const mod = url.protocol === "https:" ? require("https") : http;
    const body = JSON.stringify({
      start: "1970-01-01T00:00:00Z",
      stop: new Date(Date.now() + 86400000).toISOString(),  /* +1 day safety margin */
    });
    const req = mod.request(
      {
        method: "POST",
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        headers: {
          Authorization: `Token ${INFLUX_TOKEN}`,
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", influx: INFLUX_URL }));
    return;
  }
  /* clear endpoint: POST /api/clear → wipes the violations bucket */
  if (req.method === "POST" && req.url === "/api/clear") {
    if (!INFLUX_TOKEN) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "INFLUXDB_TOKEN not set (log-only mode)" }));
      return;
    }
    try {
      const status = await clearInflux();
      if (status === 204) {
        console.log("[SOC] bucket cleared via /api/clear");
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "cleared" }));
      } else {
        console.error(`[SOC] clear failed: InfluxDB returned ${status}`);
        res.writeHead(502).end(JSON.stringify({ error: "InfluxDB delete failed", status }));
      }
    } catch (err) {
      console.error(`[SOC] clear failed: ${err.message}`);
      res.writeHead(502).end(JSON.stringify({ error: "InfluxDB unreachable" }));
    }
    return;
  }
  if (req.method !== "POST" || req.url !== "/api/idsm-violations") {
    res.writeHead(404).end();
    return;
  }

  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", async () => {
    let event;
    try {
      event = JSON.parse(body);
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON" }));
      return;
    }
    const required = [
      "ids_message", "idsm_instance_id", "sensor_instance_id", "event_id",
      "count", "severity", "context_data_version", "payload", "payload_len",
    ];
    for (const f of required) {
      if (event[f] === undefined || event[f] === null) {
        res.writeHead(400).end(JSON.stringify({ error: `Missing field: ${f}` }));
        return;
      }
    }
    if (!VALID_SEVERITIES.has(event.severity)) {
      res.writeHead(400).end(JSON.stringify({ error: "Invalid severity" }));
      return;
    }

    const decoded = decodeContext(event.payload, event.event_id);
    const line = toLineProtocol(event, decoded, BigInt(Date.now()) * 1000000n);

    if (INFLUX_TOKEN) {
      try {
        const status = await writeToInflux(line);
        if (status !== 204) {
          console.error(`[INFLUX] write returned ${status}`);
          res.writeHead(502).end(JSON.stringify({ error: "InfluxDB error", status }));
          return;
        }
      } catch (err) {
        console.error(`[INFLUX] ${err.message}`);
        res.writeHead(502).end(JSON.stringify({ error: "InfluxDB unreachable" }));
        return;
      }
    } else {
      // no InfluxDB configured: log-only mode (useful for bring-up)
      console.log(`[SOC] ${decoded ? decoded.summary : event.payload}`);
    }

    console.log(
      `[SOC] event=0x${event.event_id.toString(16).toUpperCase()} ` +
        `${decoded ? decoded.summary : "payload=" + event.payload}`
    );
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", decoded: decoded ? decoded.summary : null }));
  });
});

server.listen(LISTEN_PORT, () => {
  console.log(`[SOC] local ingest listening on :${LISTEN_PORT}/api/idsm-violations`);
  console.log(`[SOC] InfluxDB: ${INFLUX_URL} (bucket=${INFLUX_BUCKET}, org=${INFLUX_ORG})`);
  if (!INFLUX_TOKEN) console.log("[SOC] WARNING: INFLUXDB_TOKEN not set — log-only mode");
});
