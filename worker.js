
const MODEL = "@cf/meta/llama-4-scout-17b-16e-instruct";
const MAX_BYTES = 2_000_000;

const ALLOWED_ORIGIN = "https://captainnob0di.github.io";

function json(data, status = 200, origin = "") {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });

  if (origin === ALLOWED_ORIGIN) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-APEX-Key");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Vary", "Origin");
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

function authorized(request, env) {
  const supplied = request.headers.get("X-APEX-Key");
  return Boolean(
    env.APEX_ACCESS_KEY &&
    supplied &&
    supplied === env.APEX_ACCESS_KEY
  );
}

function detectImage(bytes) {
  if (
    bytes.length >= 3 &&
    bytes[0] === 255 &&
    bytes[1] === 216 &&
    bytes[2] === 255
  ) {
    return "image/jpeg";
  }

  if (
    bytes.length >= 8 &&
    bytes[0] === 137 &&
    bytes[1] === 80 &&
    bytes[2] === 78 &&
    bytes[3] === 71 &&
    bytes[4] === 13 &&
    bytes[5] === 10 &&
    bytes[6] === 26 &&
    bytes[7] === 10
  ) {
    return "image/png";
  }

  return null;
}

function base64(bytes) {
  let result = "";
  const chunkSize = 8192;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    result += String.fromCharCode(
      ...bytes.subarray(i, i + chunkSize)
    );
  }

  return btoa(result);
}

function extractAnswer(result) {
  if (typeof result === "string") return result;

  if (typeof result?.response === "string") {
    return result.response;
  }

  if (Array.isArray(result?.choices)) {
    const content = result.choices[0]?.message?.content;
    if (typeof content === "string") return content;
  }

  return JSON.stringify(result);
}

const SYSTEM_PROMPT = `
You are ZEV DOD APEX, an AI visual analyst for PUBG gameplay screenshots.

Analyze only information supported by the supplied screenshot.

Rules:
- Never claim a map marker is a confirmed enemy.
- Never invent enemy positions, weapon names, distances, health, ammunition, or coordinates.
- Clearly distinguish visible facts from uncertain interpretations.
- If no enemy is clearly visible, say "No confirmed enemy visible".
- Discuss useful cover, obstacles, exposed approaches, and advantageous positions.
- Identify readable HUD information only when actually legible.
- Explain safer movement choices and possible flanking routes.
- Treat this as video-game tactical advice.

Respond using these sections:

VISIBLE THREATS:
COVER AND TERRAIN:
POSITIONAL ADVANTAGES:
HUD AND RESOURCES:
RECOMMENDED NEXT MOVE:
CONFIDENCE:

End with:
CALLOUT: [one short spoken tactical recommendation, maximum 18 words]
`;

async function analyzeImage(request, env, origin) {
  if (!authorized(request, env)) {
    return json({
      error: "Unauthorized",
      message: "Valid APEX access key required."
    }, 401, origin);
  }

  if (!env.AI) {
    return json({
      error: "Workers AI binding missing."
    }, 503, origin);
  }

  const contentLength = Number(
    request.headers.get("content-length") || 0
  );

  if (contentLength > MAX_BYTES + 100_000) {
    return json({
      error: "Image exceeds upload limit."
    }, 413, origin);
  }

  let form;

  try {
    form = await request.formData();
  } catch {
    return json({
      error: "Expected multipart form data."
    }, 400, origin);
  }

  const image =
    form.get("image") ||
    form.get("photo") ||
    form.get("file");

  if (!image || typeof image.arrayBuffer !== "function") {
    return json({
      error: "Missing image.",
      message: "Upload a JPEG or PNG using the image field."
    }, 400, origin);
  }

  if (image.size > MAX_BYTES) {
    return json({
      error: "Image exceeds 2 MB.",
      message: "Compress the image before uploading."
    }, 413, origin);
  }

  if (image.size === 0) {
    return json({
      error: "Image is empty."
    }, 400, origin);
  }

  const bytes = new Uint8Array(await image.arrayBuffer());
  const mime = detectImage(bytes);

  if (!mime) {
    return json({
      error: "Unsupported image format.",
      message: "Use a JPEG or PNG image."
    }, 415, origin);
  }

  const mode = form.get("mode") === "quick"
    ? "quick"
    : "full";

  const instruction = mode === "quick"
    ? "Give a concise tactical briefing. Keep all sections brief."
    : "Give a detailed tactical briefing with practical, screenshot-grounded observations.";

  const imageURL =
    "data:" + mime + ";base64," + base64(bytes);

  try {
    const result = await env.AI.run(MODEL, {
      messages: [
        {
          role: "user",
          content: [
            {
              type: "text",
              text: SYSTEM_PROMPT + "\n" + instruction
            },
            {
              type: "image_url",
              image_url: {
                url: imageURL
              }
            }
          ]
        }
      ],
      max_tokens: mode === "quick" ? 350 : 900
    });

    const callout = extractAnswer(result);

    return json({
      application: "ZEV DOD APEX",
      status: "success",
      model: MODEL,
      mode,
      callout,
      analysis: callout
    }, 200, origin);

  } catch (error) {
    return json({
      error: "Image analysis failed.",
      details: String(error?.message || error)
    }, 502, origin);
  }
}

const PASSWORD_ITERATIONS = 600000;

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(
    atob(value),
    character => character.charCodeAt(0)
  );
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(
    new Uint8Array(16)
  );

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const hash = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PASSWORD_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  return [
    "pbkdf2_sha256",
    PASSWORD_ITERATIONS,
    bytesToBase64(salt),
    bytesToBase64(new Uint8Array(hash))
  ].join("$");
}

async function verifyPassword(password, storedHash) {
  const parts = storedHash.split("$");

  if (
    parts.length !== 4 ||
    parts[0] !== "pbkdf2_sha256"
  ) {
    return false;
  }

  const iterations = Number(parts[1]);

  if (
    !Number.isInteger(iterations) ||
    iterations < 100000 ||
    iterations > 1000000
  ) {
    return false;
  }

  const salt = base64ToBytes(parts[2]);
  const expected = base64ToBytes(parts[3]);

  if (salt.length !== 16 || expected.length !== 32) {
    return false;
  }

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const actual = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    )
  );

  let difference = 0;

  for (let i = 0; i < expected.length; i++) {
    difference |= actual[i] ^ expected[i];
  }

  return difference === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
if (url.pathname === "/api/db-test") {
  if (!env.DB) {
    return Response.json(
      { status: "error", message: "D1 binding missing" },
      { status: 503 }
    );
  }

  try {
    const result = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('users', 'sessions', 'analysis_cache') ORDER BY name"
    ).all();

    return Response.json({
      application: "ZEV DOD APEX",
      database: "connected",
      tables: result.results.map(row => row.name),
      ready: result.results.length === 3
    });
  } catch (error) {
    return Response.json(
      {
        database: "error",
        message: "Database query failed"
      },
      { status: 500 }
    );
  }
}
// ZEV DOD APEX — Account Registration Route
if (url.pathname === "/api/auth/register") {
  return Response.json(
    {
      application: "ZEV DOD APEX",
      status: "not_ready",
      message: "Registration endpoint installed. Account creation is not enabled yet."
    },
    {
      status: 503,
      headers: {
        "Cache-Control": "no-store"
      }
    }
  );
}
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      if (origin !== ALLOWED_ORIGIN) {
        return new Response(null, { status: 403 });
      }

      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, X-APEX-Key",
          "Access-Control-Max-Age": "86400",
          "Vary": "Origin"
        }
      });
    }

    if (url.pathname === "/health" && request.method === "GET") {
      return json({
        application: "ZEV DOD APEX",
        status: "online",
        version: "vision-2.0",
        model: MODEL,
        aiBinding: Boolean(env.AI),
        accessKeyConfigured: Boolean(env.APEX_ACCESS_KEY),
        databaseBinding: Boolean(env.DB)
      }, 200, origin);
    }

    if (url.pathname === "/test-ai" && request.method === "GET") {
      if (!authorized(request, env)) {
        return json({
          error: "Unauthorized",
          message: "Valid APEX access key required."
        }, 401, origin);
      }

      if (!env.AI) {
        return json({
          error: "Workers AI binding missing."
        }, 503, origin);
      }

      try {
        const result = await env.AI.run(MODEL, {
          messages: [
            {
              role: "user",
              content: "Reply with exactly: APEX AI MODEL ONLINE"
            }
          ],
          max_tokens: 50
        });

        return json({
          application: "ZEV DOD APEX",
          model: MODEL,
          result: extractAnswer(result)
        }, 200, origin);

      } catch (error) {
        return json({
          error: "AI model test failed.",
          details: String(error?.message || error)
        }, 502, origin);
      }
    }

    if (url.pathname === "/analyze") {
      if (request.method !== "POST") {
        return json({
          error: "Use POST to analyze an image."
        }, 405, origin);
      }

      return analyzeImage(request, env, origin);
    }

    if (url.pathname === "/api/database-status") {
      if (!authorized(request, env)) {
        return json({
          error: "Unauthorized"
        }, 401, origin);
      }

      return json({
        application: "ZEV DOD APEX",
        databaseBinding: Boolean(env.DB),
        status: env.DB ? "connected" : "not configured"
      }, 200, origin);
    }

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return json({
      application: "ZEV DOD APEX",
      status: "backend online",
      version: "vision-2.0"
    }, 200, origin);
  }
};
