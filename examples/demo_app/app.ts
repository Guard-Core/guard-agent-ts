/**
 * demo_app serves the Guard Agent demo container: a small node:http
 * service that starts guardagent, ships one test event on boot, and
 * exposes the agent lifecycle over three routes (/ : service info,
 * /health : agent status, POST /events : emit a test event). It mirrors
 * the Python agent's examples/demo_app.
 *
 * The package is self-referenced by name ("guardagent"), which resolves
 * through the package.json exports to the built dist/, so run `npm run
 * build` (or pnpm build) first. Node 22.6+ executes this file directly via
 * type stripping (default-on from Node 23.6; pass
 * --experimental-strip-types on 22.x):
 *
 *   node --experimental-strip-types examples/demo_app/app.ts
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { GuardAgent } from "guardagent";

const DEMO_EVENT_TYPE = "custom_request_check";

const endpoint = process.env.GUARD_AGENT_ENDPOINT ?? "https://api.guard-core.com";
const projectId = process.env.GUARD_AGENT_PROJECT_ID ?? "demo-project";
const port = Number(process.env.PORT ?? 8080);

function buildTestEvent(): Record<string, unknown> {
  return {
    timestamp: new Date().toISOString(),
    event_type: DEMO_EVENT_TYPE,
    ip_address: "192.168.1.100",
    action_taken: "logged",
    reason: "Guard Agent demo container test event",
    endpoint: "/demo/test-event",
    method: "POST",
    metadata: { source: "guard-agent-demo-container" },
  };
}

function writeJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(`${JSON.stringify(payload)}\n`);
}

async function main(): Promise<void> {
  // The constructor resolves and validates the input (AgentConfigInput).
  const agent = new GuardAgent({
    endpoint,
    apiKey: process.env.GUARD_AGENT_API_KEY ?? "demo-api-key-12345",
    projectId,
    bufferSize: 10,
    flushInterval: 5,
  });

  await agent.start();

  // Boot-time test event, like the Python demo's lifespan startup.
  // sendEvent never rejects: telemetry problems surface through stats,
  // status, and logs.
  agent.sendEvent(buildTestEvent()).catch((error: unknown) => {
    console.error("boot event:", error);
  });

  const server = createServer((req: IncomingMessage, res: ServerResponse): void => {
    const path = (req.url ?? "/").split("?")[0] ?? "/";
    if (req.method === "GET" && path === "/") {
      writeJson(res, 200, { service: "guard-agent-demo", endpoint, project_id: projectId });
      return;
    }
    if (req.method === "GET" && path === "/health") {
      agent
        .getStatus()
        .then((status) => writeJson(res, 200, { status: status.status }))
        .catch((error: unknown) => writeJson(res, 500, { error: String(error) }));
      return;
    }
    if (req.method === "POST" && path === "/events") {
      const event = buildTestEvent();
      agent
        .sendEvent(event)
        .then(() => writeJson(res, 200, { emitted: DEMO_EVENT_TYPE }))
        .catch((error: unknown) => writeJson(res, 500, { error: String(error) }));
      return;
    }
    if (path === "/" || path === "/health") {
      writeJson(res, 405, { error: "GET only" });
      return;
    }
    if (path === "/events") {
      writeJson(res, 405, { error: "POST only" });
      return;
    }
    writeJson(res, 404, { error: "not found" });
  });

  const shutdown = async (): Promise<void> => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    // Final flush + confirm.
    await agent.stop();
    process.exit(0);
  };

  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());

  server.listen(port, "0.0.0.0", () => {
    console.log(
      `guard-agent demo listening on 0.0.0.0:${port} (endpoint ${endpoint}, project ${projectId})`,
    );
  });
}

void main();
