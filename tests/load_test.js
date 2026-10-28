// k6 load + attack-simulation test for ZeroL7.
//
// Usage:
//   k6 run tests/load_test.js
//   k6 run -e BASE_URL=http://localhost:8080 tests/load_test.js
//
// What it checks:
//   - legitimate traffic ("benign" scenario) is served with low latency
//     and a healthy success rate under concurrent load.
//   - simulated SQLi/XSS/path-traversal attacks ("attack" scenario) are
//     rejected with 403 from the WAF, not forwarded to a backend.
//   - p95 end-to-end latency (through TLS/parse/WAF/routing) stays within
//     the project's budget even while attack traffic is also hitting
//     the proxy concurrently.
import http from "k6/http";
import { check } from "k6";
import { Rate, Trend } from "k6/metrics";

const payloads = JSON.parse(open("./exploit_payloads.json"));

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";

const wafBlockRate = new Rate("waf_block_rate");
const benignSuccessRate = new Rate("benign_success_rate");
const benignLatency = new Trend("benign_latency_ms");

export const options = {
  scenarios: {
    benign_traffic: {
      executor: "ramping-vus",
      exec: "benign",
      startVUs: 0,
      stages: [
        { duration: "15s", target: 50 },
        { duration: "30s", target: 50 },
        { duration: "10s", target: 0 },
      ],
    },
    attack_traffic: {
      executor: "constant-vus",
      exec: "attack",
      vus: 10,
      duration: "45s",
      startTime: "5s",
    },
  },
  thresholds: {
    benign_success_rate: ["rate>0.99"],
    waf_block_rate: ["rate>0.99"],
    benign_latency_ms: ["p(95)<200"],
  },
};

export function benign() {
  const samples = payloads.benign;
  const q = samples[Math.floor(Math.random() * samples.length)];
  const res = http.get(`${BASE_URL}/api/search?${q}`);
  benignSuccessRate.add(res.status === 200);
  benignLatency.add(res.timings.duration);
  check(res, { "benign request succeeds": (r) => r.status === 200 });
}

export function attack() {
  const categories = ["sqli", "xss", "path_traversal"];
  const category = categories[Math.floor(Math.random() * categories.length)];
  const samples = payloads[category];
  const q = samples[Math.floor(Math.random() * samples.length)];
  const res = http.get(`${BASE_URL}/api/search?${q}`, {
    headers: { "X-Test-Category": category },
  });
  wafBlockRate.add(res.status === 403);
  check(res, { "attack is blocked with 403": (r) => r.status === 403 });
}
