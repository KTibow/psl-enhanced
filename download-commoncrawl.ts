import { spawn } from "node:child_process";
import { once } from "node:events";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";

const BASE =
  "https://data.commoncrawl.org/projects/hyperlinkgraph/cc-main-2025-26-nov-dec-jan/host";
const PATHS_URL = `${BASE}/cc-main-2025-26-nov-dec-jan-host-vertices.paths.gz`;

const OUT = "data/hosts.txt";
const SHARD_DIR = "data/commoncrawl-shards";
const WORKERS = 4;
const KEEP_SHARDS = false;
const WORKER_MODE_ENV = "COMMONCRAWL_WORKER_MODE";
const RELPATH_ENV = "COMMONCRAWL_REL_PATH";
const SHARD_OUT_ENV = "COMMONCRAWL_SHARD_OUT";

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchRetry(url: string, tries: number = 4): Promise<Response> {
  let lastErr: Error = new Error("Unreachable");
  for (let i = 1; i <= tries; i++) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      return res;
    } catch (e) {
      lastErr = e as Error;
      const backoff = Math.min(2000 * i, 8000);
      console.error(`fetch failed (${i}/${tries}) ${url}: ${e.message}`);
      if (i < tries) await sleep(backoff);
    }
  }
  throw lastErr;
}

async function gunzipToText(res: Response): Promise<string> {
  if (typeof DecompressionStream !== "function") {
    throw new Error("DecompressionStream not available; use Node 20+.");
  }
  if (!res.body) {
    throw new Error("empty response body");
  }
  const ds = new DecompressionStream("gzip");
  const stream = res.body.pipeThrough(ds);
  return await new Response(stream).text();
}

async function writeShardHosts(url: string, outPath: string): Promise<void> {
  const shardRes = await fetchRetry(url);
  if (!shardRes.body) {
    throw new Error("empty shard response body");
  }
  const textStream = shardRes.body
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new TextDecoderStream());
  const reader = textStream.getReader();
  const out = createWriteStream(outPath, { flags: "w" });
  let carry = "";

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      carry += value;

      while (true) {
        const newline = carry.indexOf("\n");
        if (newline === -1) break;

        let line = carry.slice(0, newline);
        carry = carry.slice(newline + 1);
        if (line.endsWith("\r")) line = line.slice(0, -1);

        const tab = line.indexOf("\t");
        if (tab === -1) continue;
        if (!out.write(line.slice(tab + 1) + "\n")) {
          await once(out, "drain");
        }
      }
    }

    if (carry.length > 0) {
      let line = carry;
      if (line.endsWith("\r")) line = line.slice(0, -1);
      const tab = line.indexOf("\t");
      if (tab !== -1 && !out.write(line.slice(tab + 1) + "\n")) {
        await once(out, "drain");
      }
    }
  } finally {
    reader.releaseLock();
    out.end();
    await once(out, "finish");
  }
}

function runShardSubprocess(relpath: string, shardOut: string): Promise<void> {
  const scriptPath = fileURLToPath(import.meta.url);
  const child = spawn(process.execPath, [scriptPath], {
    env: {
      ...process.env,
      [WORKER_MODE_ENV]: "1",
      [RELPATH_ENV]: relpath,
      [SHARD_OUT_ENV]: shardOut,
    },
    stdio: ["ignore", "inherit", "inherit"],
  });

  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new Error(
          `worker failed for ${relpath} (code=${String(code)}, signal=${String(signal)})`,
        ),
      );
    });
  });
}

async function mapLimit<T, R>(
  items: readonly T[],
  concurrency: number,
  run: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;

  async function worker(): Promise<void> {
    while (true) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await run(items[index], index);
    }
  }

  const workers = Array.from(
    { length: Math.min(concurrency, items.length) },
    () => worker(),
  );
  await Promise.all(workers);
  return results;
}

async function concatFiles(
  inputs: readonly string[],
  outPath: string,
): Promise<void> {
  const out = createWriteStream(outPath, { flags: "w" });
  try {
    for (const input of inputs) {
      const stream = createReadStream(input);
      for await (const chunk of stream) {
        if (!out.write(chunk)) await once(out, "drain");
      }
    }
  } finally {
    out.end();
    await once(out, "finish");
  }
}

async function runWorkerMode(): Promise<void> {
  const relpath = process.env[RELPATH_ENV];
  const shardOut = process.env[SHARD_OUT_ENV];
  if (!relpath || !shardOut) {
    throw new Error("worker mode missing shard env vars");
  }
  const url = `https://data.commoncrawl.org/${relpath}`;
  await mkdir(dirname(shardOut), { recursive: true });
  await writeShardHosts(url, shardOut);
}

async function runParentMode(): Promise<void> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  await new Promise<void>((resolve) => {
    rl.question(
      "Do you want to proceed with downloading and processing the data? (y/N): ",
      (answer) => {
        rl.close();
        if (answer.toLowerCase() !== "y") {
          console.error("Aborted.");
          process.exit(0);
        }
        resolve();
      },
    );
  });

  console.error(`Fetching shard list: ${PATHS_URL}`);
  const pathsRes = await fetchRetry(PATHS_URL);
  const pathsText = await gunzipToText(pathsRes);
  const relpaths = pathsText
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);

  console.error(`Shards: ${relpaths.length}`);
  await rm(SHARD_DIR, { recursive: true, force: true });
  await mkdir(SHARD_DIR, { recursive: true });

  const workerCount = Math.max(1, Math.min(WORKERS, relpaths.length));
  console.error(`Workers: ${workerCount}`);

  const shardFiles = await mapLimit(
    relpaths,
    workerCount,
    async (rel, index) => {
      const shardOut = join(
        SHARD_DIR,
        `shard-${String(index + 1).padStart(5, "0")}.txt`,
      );
      console.error(`[${index + 1}/${relpaths.length}] ${rel}`);
      await runShardSubprocess(rel, shardOut);
      return shardOut;
    },
  );

  await mkdir(dirname(OUT), { recursive: true });
  console.error(`Combining ${shardFiles.length} shard files into ${OUT}`);
  await concatFiles(shardFiles, OUT);

  if (!KEEP_SHARDS) {
    await rm(SHARD_DIR, { recursive: true, force: true });
  }

  console.error("Done.");
}

if (process.env[WORKER_MODE_ENV] === "1") {
  await runWorkerMode();
} else {
  await runParentMode();
}
