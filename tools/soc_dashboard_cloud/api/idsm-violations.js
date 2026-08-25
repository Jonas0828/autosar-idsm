const VALID_SEVERITIES = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

const REQUIRED_FIELDS = [
  "monitor_id",
  "event_id",
  "timestamp_ms",
  "severity",
  "payload",
  "payload_len",
];

function toLineProtocol(event, receivedAtNs) {
  const monitorHex = `0x${event.monitor_id.toString(16).toUpperCase().padStart(4, "0")}`;

  // Tags: indexed, low-cardinality fields
  const tags = [
    `severity=${event.severity}`,
    `monitor_id=${monitorHex}`,
  ].join(",");

  // Fields: all numeric + string values (strings must be quoted)
  const fields = [
    `event_id=${event.event_id}i`,
    `timestamp_ms=${event.timestamp_ms}i`,
    `payload_len=${event.payload_len}i`,
    `monitor_id_int=${event.monitor_id}i`,
    `payload="${event.payload}"`,
  ].join(",");

  return `idsm_violations,${tags} ${fields} ${receivedAtNs}`;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Parse body
  let body;
  try {
    body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: "Invalid JSON" });
  }

  // Validate required fields
  for (const field of REQUIRED_FIELDS) {
    if (body[field] === undefined || body[field] === null) {
      return res.status(400).json({ error: `Missing field: ${field}` });
    }
  }

  // Validate severity
  if (!VALID_SEVERITIES.has(body.severity)) {
    return res
      .status(400)
      .json({ error: `Invalid severity: ${body.severity}` });
  }

  // Validate types
  if (
    typeof body.monitor_id !== "number" ||
    typeof body.event_id !== "number" ||
    typeof body.timestamp_ms !== "number" ||
    typeof body.payload_len !== "number" ||
    typeof body.payload !== "string"
  ) {
    return res.status(400).json({ error: "Invalid field types" });
  }

  const {
    INFLUXDB_URL,
    INFLUXDB_TOKEN,
    INFLUXDB_ORG,
    INFLUXDB_BUCKET,
  } = process.env;

  if (!INFLUXDB_URL || !INFLUXDB_TOKEN || !INFLUXDB_ORG || !INFLUXDB_BUCKET) {
    console.error("Missing InfluxDB environment variables");
    return res.status(500).json({ error: "Server misconfigured" });
  }

  const receivedAtNs = BigInt(Date.now()) * 1_000_000n;
  const lineProtocol = toLineProtocol(body, receivedAtNs);

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
    return res.status(502).json({ error: "InfluxDB write error", status: influxRes.status, detail: text });
  }

  return res.status(200).json({ status: "ok" });
}
