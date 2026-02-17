#!/usr/bin/env node

import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { Octokit } from "octokit";

const OWNER = "publicsuffix";
const REPO = "list";
const OUTPUT_DIR = path.resolve("data", "prs");
const MAX_PRS_TO_ARCHIVE = Number.POSITIVE_INFINITY;
const CONCURRENCY = 4;
const PROGRESS_EVERY = 25;
const PER_PAGE = 100;
const REQUEST_TIMEOUT_MS = 30_000;
const USER_AGENT = "psl-enhanced-pr-archiver";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN ?? readTokenFromDotEnv();
const API_BASE_URL = `https://api.github.com/repos/${OWNER}/${REPO}`;

const octokit = new Octokit({
  auth: GITHUB_TOKEN || undefined,
  request: {
    timeout: REQUEST_TIMEOUT_MS,
  },
  userAgent: USER_AGENT,
});

async function main() {
  rmSync(OUTPUT_DIR, { recursive: true, force: true });
  mkdirSync(OUTPUT_DIR, { recursive: true });

  console.log(`Streaming PRs for ${OWNER}/${REPO}...`);

  const failures = [];
  const stats = {
    archived: 0,
    failed: 0,
  };
  const inFlight = new Set();
  let prsSeen = 0;
  let prsScheduled = 0;
  let prsCompleted = 0;
  const workerLimit = Math.max(1, CONCURRENCY);

  for await (const response of octokit.paginate.iterator(octokit.rest.pulls.list, {
    owner: OWNER,
    repo: REPO,
    state: "all",
    sort: "created",
    direction: "asc",
    per_page: PER_PAGE,
  })) {
    for (const pull of response.data) {
      prsSeen += 1;
      if (prsScheduled >= MAX_PRS_TO_ARCHIVE) {
        break;
      }

      while (inFlight.size >= workerLimit) {
        await Promise.race(inFlight);
      }

      prsScheduled += 1;
      const task = runArchive(pull.number, stats, failures).finally(() => {
        inFlight.delete(task);
        prsCompleted += 1;
        if (prsCompleted % PROGRESS_EVERY === 0 || prsCompleted === prsScheduled) {
          console.log(
            `Progress completed=${prsCompleted} scheduled=${prsScheduled} seen=${prsSeen} archived=${stats.archived} failed=${stats.failed}`,
          );
        }
      });
      inFlight.add(task);
    }

    if (prsScheduled >= MAX_PRS_TO_ARCHIVE) {
      break;
    }
  }

  await Promise.all(inFlight);

  const summary = {
    archived_at: new Date().toISOString(),
    owner: OWNER,
    repo: REPO,
    output_dir: OUTPUT_DIR,
    max_prs_to_archive: Number.isFinite(MAX_PRS_TO_ARCHIVE) ? MAX_PRS_TO_ARCHIVE : "infinity",
    total_prs_seen: prsSeen,
    prs_scheduled: prsScheduled,
    prs_completed: prsCompleted,
    stats,
    failed_prs: failures,
  };

  writeFileSync(path.join(OUTPUT_DIR, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);

  console.log("Done.");
  console.log(`Archived: ${stats.archived}, failed: ${stats.failed}, completed: ${prsCompleted}`);
  if (failures.length > 0) {
    console.log(`Failure details saved to ${path.join(OUTPUT_DIR, "summary.json")}`);
  }
}

async function runArchive(prNumber, stats, failures) {
  try {
    await archivePr(prNumber);
    stats.archived += 1;
  } catch (error) {
    stats.failed += 1;
    failures.push({
      pr_number: prNumber,
      error: error instanceof Error ? error.message : String(error),
    });
    console.error(`failed PR #${prNumber}:`, error);
  }
}

async function archivePr(prNumber) {
  const outFile = path.join(OUTPUT_DIR, `pr-${prNumber}.json`);

  const urls = {
    pull: `${API_BASE_URL}/pulls/${prNumber}`,
  };

  const payload = {
    archived_at: new Date().toISOString(),
    owner: OWNER,
    repo: REPO,
    pr_number: prNumber,
    urls,
    data: {
      pull: null,
    },
  };

  payload.data.pull = (
    await octokit.rest.pulls.get({
      owner: OWNER,
      repo: REPO,
      pull_number: prNumber,
    })
  ).data;

  const tmpFile = `${outFile}.tmp`;
  writeFileSync(tmpFile, `${JSON.stringify(payload, null, 2)}\n`);
  renameSync(tmpFile, outFile);
}

function readTokenFromDotEnv() {
  try {
    const envFile = path.resolve(".env");
    const raw = readFileSync(envFile, "utf8");
    const lines = raw.split(/\r?\n/);

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        continue;
      }

      const separatorIndex = trimmed.indexOf("=");
      if (separatorIndex <= 0) {
        continue;
      }

      const key = trimmed.slice(0, separatorIndex).trim();
      if (key !== "GITHUB_TOKEN") {
        continue;
      }

      const value = trimmed.slice(separatorIndex + 1).trim();
      return stripQuotes(value);
    }
  } catch {
    return "";
  }

  return "";
}

function stripQuotes(value) {
  if (value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1);
  }
  if (value.startsWith("'") && value.endsWith("'")) {
    return value.slice(1, -1);
  }

  return value;
}

await main();
