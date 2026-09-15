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

const DETECTOR_NAMES = {
  1: "PORT_SCAN", 2: "RATE_FLOOD", 3: "FLAG_ANOMALY", 4: "RULE_HIT",
  5: "DOIP", 6: "SOME_IP", 7: "REASSEMBLY", 8: "CROSS_BORDER",
  9: "TLS", 10: "HTTP", 11: "DNS", 12: "ARP_SPOOF", 100: "SURICATA",
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

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", influx: INFLUX_URL }));
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

    const decoded = decodeContext(event.payload);
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
