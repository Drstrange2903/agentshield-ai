import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

await import("./detector.js");

const { analyze } = globalThis.AgentShield;
const root = fileURLToPath(new URL(".", import.meta.url));
const port = Number(process.env.PORT || 4173);

async function loadEnvFile() {
  try {
    const envFile = await readFile(join(root, ".env"), "utf-8");
    for (const line of envFile.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const separator = trimmed.indexOf("=");
      if (separator === -1) continue;
      const key = trimmed.slice(0, separator).trim();
      const value = trimmed.slice(separator + 1).trim().replace(/^["']|["']$/g, "");
      if (key && process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch {
    // .env is optional. Without it, the server keeps the local detector active.
  }
}

await loadEnvFile();

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".md": "text/plain; charset=utf-8"
};

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 100_000) {
        reject(new Error("Request body is too large."));
        request.destroy();
      }
    });
    request.on("end", () => {
      try {
        resolve(JSON.parse(body || "{}"));
      } catch {
        reject(new Error("Invalid JSON request body."));
      }
    });
  });
}

async function azureClassify(content, localResult) {
  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;
  const apiKey = process.env.AZURE_OPENAI_API_KEY;
  const apiVersion = process.env.AZURE_OPENAI_API_VERSION || "2024-10-21";

  if (!endpoint || !deployment || !apiKey) {
    return {
      ...localResult,
      provider: "local",
      matches: [
        {
          title: "Azure Not Configured",
          tag: "Local",
          explanation: "Set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT, and AZURE_OPENAI_API_KEY to enable Azure enhanced scanning.",
          action: "Use the local detector until Azure credentials are configured."
        },
        ...localResult.matches
      ]
    };
  }

  const url = `${endpoint.replace(/\/$/, "")}/openai/deployments/${deployment}/chat/completions?api-version=${apiVersion}`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "api-key": apiKey
    },
    body: JSON.stringify({
      temperature: 0,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: "You are an enterprise AI security classifier. Return strict JSON with keys score, level, decision, matches. matches must be an array of objects with title, tag, explanation, action. Classify prompt injection, secret exfiltration, tool abuse, stealth, and safety bypass risk."
        },
        {
          role: "user",
          content: JSON.stringify({
            content,
            local_firewall_result: localResult
          })
        }
      ]
    })
  });

  if (!response.ok) {
    throw new Error(`Azure OpenAI returned ${response.status}`);
  }

  const data = await response.json();
  const parsed = JSON.parse(data.choices?.[0]?.message?.content || "{}");
  return {
    score: Number(parsed.score ?? localResult.score),
    level: parsed.level || localResult.level,
    decision: parsed.decision || localResult.decision,
    className: Number(parsed.score ?? localResult.score) >= 65 ? "high" : Number(parsed.score ?? localResult.score) >= 30 ? "medium" : "",
    provider: "azure-openai",
    matches: Array.isArray(parsed.matches) && parsed.matches.length ? parsed.matches : localResult.matches
  };
}

async function handleAnalyze(request, response) {
  try {
    const { content = "" } = await readJson(request);
    const localResult = analyze(String(content));
    const result = await azureClassify(String(content), localResult);
    response.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    response.end(JSON.stringify(result));
  } catch (error) {
    response.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
    response.end(JSON.stringify({ error: error.message }));
  }
}

async function serveStatic(urlPath, response) {
  const requestedPath = urlPath === "/" ? "index.html" : decodeURIComponent(urlPath.slice(1));
  const safePath = normalize(requestedPath).replace(/^(\.\.[/\\])+/, "");
  const absolutePath = join(root, safePath);

  try {
    const file = await readFile(absolutePath);
    response.writeHead(200, { "Content-Type": mimeTypes[extname(absolutePath)] || "application/octet-stream" });
    response.end(file);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found");
  }
}

createServer((request, response) => {
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

  if (request.method === "POST" && url.pathname === "/api/analyze") {
    void handleAnalyze(request, response);
    return;
  }

  if (request.method === "GET") {
    void serveStatic(url.pathname, response);
    return;
  }

  response.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("Method not allowed");
}).listen(port, () => {
  console.log(`AgentShield AI running at http://localhost:${port}`);
});
