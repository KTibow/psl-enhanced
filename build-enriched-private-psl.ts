import { spawnSync } from "node:child_process";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const PSL_DIR = path.resolve("psl");
const PSL_FILE = path.join(PSL_DIR, "public_suffix_list.dat");
const PRS_DIR = path.resolve("data", "prs");
const DOMAIN_CONTEXT_DIR = path.resolve("data", "domain-context");
const OUTPUT_FILE = path.resolve("output.dat");

const BEGIN_PRIVATE_DOMAINS_MARKER = "// ===BEGIN PRIVATE DOMAINS===";
const END_PRIVATE_DOMAINS_MARKER = "// ===END PRIVATE DOMAINS===";
const MANUAL_BLAME_IGNORE_COMMITS = [
  "029c9a14913ddf373cd595b49cfb17677bf1c136",
  "cabeda8651aa3ca353cecca9c6bc8ad77cd04751",
  "f229d7f87051bb6197b315f42adae05cb68e33b5",
  "4523e5ff426790935af9360e8d006de4f9f49361",
  "10e18658b9da01a79b44194d216b0dd3056cbfa0",
  "ff4958dd9cb7197d435ceadd053f9dc8da7852dc",
  "48e78df93e0010ed35fc8ee8ec8dcba51edbe951",
  "0de6f8ebdafd75c3b3ea06185a95c999fefe4850",
  "e4051df5af7d0c38b66cbc075205d5660feed7b2",
  "fb4a6bce72a86feaf6c38f0a43cd05baf97a9258",
];
const PSLTOOL_FMT_COMMIT_GREP = "psltool fmt";

const MAX_GIT_BUFFER_BYTES = 256 * 1024 * 1024;
const MAX_HEADER_BODY_CHARS = 8_000;
const MAX_CONTEXT_TEXT_CHARS = 260;

const LABEL_PATTERN = String.raw`[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?`;
const LABEL_REGEX = new RegExp(`^${LABEL_PATTERN}$`, "u");
const DOMAIN_EXTRACTOR = new RegExp(
  [
    String.raw`(?:[a-z][a-z0-9+.-]*:\/\/(?:[^\s/@]+@)?((?:${LABEL_PATTERN}\.)+${LABEL_PATTERN})(?::\d+)?(?:[/?#][^\s<>"')\]]*)?)`,
    String.raw`(?:[\p{L}\p{N}._%+-]+@((?:${LABEL_PATTERN}\.)+${LABEL_PATTERN}))`,
    String.raw`(?:^|[^\p{L}\p{N}-])(?:!|\*\.)((?:${LABEL_PATTERN}\.)+${LABEL_PATTERN})(?=$|[^\p{L}\p{N}-])`,
    String.raw`(?:^|[^\p{L}\p{N}-])\.(${LABEL_PATTERN})(?=$|[^\p{L}\p{N}-])`,
    String.raw`(?:^|[^\p{L}\p{N}-])((?:${LABEL_PATTERN}\.)+${LABEL_PATTERN})(?!@)(?=$|[^\p{L}\p{N}-])`,
  ].join("|"),
  "giu",
);
const HAS_LETTER_PATTERN = /\p{L}/u;

const SECTION_ALIASES: Record<string, string> = {
  "description of organization": "Description of Organization",
  "reason for psl inclusion": "Reason for PSL Inclusion",
  "dns verification via dig": "DNS verification via dig",
  "run syntax checker": "Run Syntax Checker",
  "run syntax checker (make test)": "Run Syntax Checker",
};

const PRIMARY_BODY_SECTIONS = [
  "Description of Organization",
  "Reason for PSL Inclusion",
] as const;

type PrivateSection = {
  lines: string[];
  startLine: number;
  endLine: number;
};

type BlameRecord = {
  commit: string;
  sourceLine: number;
  lineNumber: number;
  author: string;
  authorMail: string;
  summary: string;
  text: string;
};

type PullRecord = {
  number: number;
  title: string;
  body: string | null;
  user?: {
    login?: string | null;
  } | null;
};

type DomainContextSummary = {
  summary: string;
};

type BuildSummary = {
  outputPath: string;
  privateLines: number;
  blameRecords: number;
  ignoredCommits: number;
  ignoredFmtCommits: number;
  resolvedIgnoredLines: number;
  unresolvedIgnoredLines: number;
  prsLoaded: number;
  contextFile: string;
  contextsLoaded: number;
  contextParseFailures: number;
};

export async function buildEnrichedPrivatePslOutput(): Promise<BuildSummary> {
  const pslSource = await readFile(PSL_FILE, "utf8");
  const pslLines = splitLines(pslSource);
  const privateSection = extractPrivateSection(pslLines);
  const ignoredCommits = collectBlameIgnoreCommits();

  console.log(
    `Loaded private section: lines=${privateSection.lines.length} range=${privateSection.startLine}-${privateSection.endLine}`,
  );
  console.log(
    `Blame ignore commits: total=${ignoredCommits.all.length} psltool_fmt=${ignoredCommits.psltoolFmt.length}`,
  );

  const blameOutput = runGitInPsl([
    "blame",
    "-M",
    "-C",
    "-C",
    ...buildIgnoreRevArgs(ignoredCommits.all),
    "-L",
    `${privateSection.startLine},${privateSection.endLine}`,
    "--line-porcelain",
    "--",
    "public_suffix_list.dat",
  ]);
  const blameRecords = parseBlamePorcelain(blameOutput);

  if (blameRecords.length !== privateSection.lines.length) {
    throw new Error(
      `Blame record count mismatch. expected=${privateSection.lines.length} actual=${blameRecords.length}`,
    );
  }

  for (let i = 0; i < blameRecords.length; i += 1) {
    const expectedLine = privateSection.startLine + i;
    if (blameRecords[i].lineNumber !== expectedLine) {
      throw new Error(
        `Unexpected blame line number at index=${i}. expected=${expectedLine} actual=${blameRecords[i].lineNumber}`,
      );
    }
  }

  const repaired = repairIgnoredCommitAttribution(
    blameRecords,
    privateSection,
    ignoredCommits.all,
  );

  const prNumbers = collectReferencedPrNumbers(repaired.records);
  const prMap = await loadPullRequests(prNumbers);
  const latestDomainContextPath = await findLatestDomainContextPath();
  const domainContext = await loadDomainContext(latestDomainContextPath);

  const rendered = renderEnrichedPrivateSection(
    privateSection.lines,
    repaired.records,
    prMap,
    domainContext.contextByDomain,
  );

  await writeFile(OUTPUT_FILE, `${rendered.join("\n")}\n`, "utf8");

  console.log(`Wrote ${rendered.length} lines to ${path.relative(process.cwd(), OUTPUT_FILE)}`);

  return {
    outputPath: OUTPUT_FILE,
    privateLines: privateSection.lines.length,
    blameRecords: repaired.records.length,
    ignoredCommits: ignoredCommits.all.length,
    ignoredFmtCommits: ignoredCommits.psltoolFmt.length,
    resolvedIgnoredLines: repaired.resolvedCount,
    unresolvedIgnoredLines: repaired.remainingIgnoredCount,
    prsLoaded: prMap.size,
    contextFile: latestDomainContextPath,
    contextsLoaded: domainContext.contextByDomain.size,
    contextParseFailures: domainContext.parseFailures,
  };
}

function splitLines(text: string) {
  return text.split(/\r?\n/);
}

function extractPrivateSection(pslLines: string[]): PrivateSection {
  const beginIndex = pslLines.indexOf(BEGIN_PRIVATE_DOMAINS_MARKER);
  const endIndex = pslLines.indexOf(END_PRIVATE_DOMAINS_MARKER);

  if (beginIndex === -1) {
    throw new Error(`Missing marker: ${BEGIN_PRIVATE_DOMAINS_MARKER}`);
  }
  if (endIndex === -1) {
    throw new Error(`Missing marker: ${END_PRIVATE_DOMAINS_MARKER}`);
  }
  if (beginIndex >= endIndex) {
    throw new Error("Private domains markers are out of order.");
  }

  return {
    lines: pslLines.slice(beginIndex + 1, endIndex),
    startLine: beginIndex + 2,
    endLine: endIndex,
  };
}

function parseBlamePorcelain(output: string): BlameRecord[] {
  const records: BlameRecord[] = [];
  const lines = splitLines(output);
  let current: Partial<BlameRecord> | null = null;

  for (const line of lines) {
    const headerMatch = line.match(/^([0-9a-f]{40}) (\d+) (\d+)(?: (\d+))?$/);
    if (headerMatch) {
      current = {
        commit: headerMatch[1],
        sourceLine: Number(headerMatch[2]),
        lineNumber: Number(headerMatch[3]),
      };
      continue;
    }

    if (!current) {
      continue;
    }

    if (line.startsWith("\t")) {
      records.push({
        commit: current.commit ?? "",
        sourceLine: current.sourceLine ?? 0,
        lineNumber: current.lineNumber ?? 0,
        author: current.author ?? "",
        authorMail: current.authorMail ?? "",
        summary: current.summary ?? "",
        text: line.slice(1),
      });
      current = null;
      continue;
    }

    const firstSpace = line.indexOf(" ");
    const key = firstSpace === -1 ? line : line.slice(0, firstSpace);
    const value = firstSpace === -1 ? "" : line.slice(firstSpace + 1);
    if (key === "author") {
      current.author = value;
    } else if (key === "author-mail") {
      current.authorMail = value;
    } else if (key === "summary") {
      current.summary = value;
    }
  }

  if (current) {
    throw new Error("Failed to parse blame output: dangling record.");
  }

  return records;
}

function collectBlameIgnoreCommits() {
  const psltoolFmt = runGitInPsl([
    "log",
    "--format=%H",
    "--regexp-ignore-case",
    `--grep=${PSLTOOL_FMT_COMMIT_GREP}`,
    "--",
    "public_suffix_list.dat",
  ])
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^[0-9a-f]{40}$/u.test(line));

  const combined = new Set<string>();
  for (const commit of MANUAL_BLAME_IGNORE_COMMITS) {
    combined.add(commit);
  }
  for (const commit of psltoolFmt) {
    combined.add(commit);
  }

  return {
    all: [...combined],
    psltoolFmt,
  };
}

function buildIgnoreRevArgs(commits: string[]) {
  const args: string[] = [];
  for (const commit of commits) {
    args.push("--ignore-rev", commit);
  }
  return args;
}

function repairIgnoredCommitAttribution(
  records: BlameRecord[],
  currentSection: PrivateSection,
  ignoredCommits: string[],
) {
  const repairedRecords = [...records];
  let resolvedCount = 0;
  const ignoredCommitSet = new Set(ignoredCommits);
  const maxPasses = Math.max(3, ignoredCommits.length + 2);
  let remainingIgnoredCount = repairedRecords.filter((record) =>
    ignoredCommitSet.has(record.commit),
  ).length;

  for (let pass = 1; pass <= maxPasses && remainingIgnoredCount > 0; pass += 1) {
    let resolvedInPass = 0;

    for (const ignoredCommit of ignoredCommits) {
      const indices = repairedRecords
        .map((record, index) => ({ record, index }))
        .filter(({ record }) => record.commit === ignoredCommit)
        .map(({ index }) => index);

      if (indices.length === 0) {
        continue;
      }

      const parentRevision = `${ignoredCommit}^`;
      let parentSource = "";
      try {
        parentSource = runGitInPsl(["show", `${parentRevision}:public_suffix_list.dat`]);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(
          `Ignore repair skipped for ${ignoredCommit.slice(0, 12)}: unable to load parent file: ${message}`,
        );
        continue;
      }
      const parentLines = splitLines(parentSource);
      const parentSection = extractPrivateSection(parentLines);

      let parentBlameOutput = "";
      try {
        parentBlameOutput = runGitInPsl([
          "blame",
          "-M",
          "-C",
          "-C",
          ...buildIgnoreRevArgs(ignoredCommits),
          parentRevision,
          "-L",
          `${parentSection.startLine},${parentSection.endLine}`,
          "--line-porcelain",
          "--",
          "public_suffix_list.dat",
        ]);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(
          `Ignore repair skipped for ${ignoredCommit.slice(0, 12)}: unable to blame parent: ${message}`,
        );
        continue;
      }
      const parentBlameRecords = parseBlamePorcelain(parentBlameOutput);
      const parentBlameByLine = new Map<number, BlameRecord>();
      for (const record of parentBlameRecords) {
        parentBlameByLine.set(record.lineNumber, record);
      }

      const parentLineNumbersByText = new Map<string, number[]>();
      for (
        let lineNumber = parentSection.startLine;
        lineNumber <= parentSection.endLine;
        lineNumber += 1
      ) {
        const text = parentLines[lineNumber - 1] ?? "";
        const existing = parentLineNumbersByText.get(text);
        if (existing) {
          existing.push(lineNumber);
        } else {
          parentLineNumbersByText.set(text, [lineNumber]);
        }
      }

      let resolvedForCommit = 0;

      for (const index of indices) {
        const lineText = repairedRecords[index].text;
        const candidates = parentLineNumbersByText.get(lineText) ?? [];
        if (candidates.length === 0) {
          continue;
        }

        const candidateLine = chooseParentCandidateLine({
          currentIndex: index,
          currentRecords: repairedRecords,
          parentCandidates: candidates,
          parentLines,
          parentSection,
          currentSection,
        });
        if (candidateLine === null) {
          continue;
        }

        const parentBlame = parentBlameByLine.get(candidateLine);
        if (!parentBlame) {
          continue;
        }

        repairedRecords[index] = {
          ...repairedRecords[index],
          commit: parentBlame.commit,
          sourceLine: parentBlame.sourceLine,
          author: parentBlame.author,
          authorMail: parentBlame.authorMail,
          summary: parentBlame.summary,
        };
        resolvedForCommit += 1;
      }

      resolvedCount += resolvedForCommit;
      resolvedInPass += resolvedForCommit;

      const remainingForCommit = repairedRecords.filter(
        (record) => record.commit === ignoredCommit,
      ).length;
      console.log(
        `Ignore repair pass=${pass} ${ignoredCommit.slice(0, 12)}: targeted=${indices.length} resolved=${resolvedForCommit} remaining=${remainingForCommit}`,
      );
    }

    remainingIgnoredCount = repairedRecords.filter((record) =>
      ignoredCommitSet.has(record.commit),
    ).length;
    console.log(
      `Ignore repair pass=${pass} summary: resolved=${resolvedInPass} remaining=${remainingIgnoredCount}`,
    );

    if (resolvedInPass === 0) {
      break;
    }
  }

  return {
    records: repairedRecords,
    resolvedCount,
    remainingIgnoredCount,
  };
}

function chooseParentCandidateLine(options: {
  currentIndex: number;
  currentRecords: BlameRecord[];
  parentCandidates: number[];
  parentLines: string[];
  parentSection: PrivateSection;
  currentSection: PrivateSection;
}) {
  const {
    currentIndex,
    currentRecords,
    parentCandidates,
    parentLines,
    parentSection,
    currentSection,
  } = options;
  if (parentCandidates.length === 0) {
    return null;
  }
  if (parentCandidates.length === 1) {
    return parentCandidates[0];
  }

  const prev1 = currentRecords[currentIndex - 1]?.text;
  const next1 = currentRecords[currentIndex + 1]?.text;
  const prev2 = currentRecords[currentIndex - 2]?.text;
  const next2 = currentRecords[currentIndex + 2]?.text;

  let candidates = narrowByNeighbor(parentCandidates, parentLines, parentSection, -1, prev1);
  candidates = narrowByNeighbor(candidates, parentLines, parentSection, +1, next1);

  if (candidates.length === 1) {
    return candidates[0];
  }

  const expectedLine = toExpectedParentLine(
    currentIndex,
    currentSection,
    parentSection,
    currentRecords.length,
  );
  const scored = candidates.map((lineNumber) => ({
    lineNumber,
    score:
      scoreNeighborMatch(lineNumber, parentLines, parentSection, -1, prev1) * 4 +
      scoreNeighborMatch(lineNumber, parentLines, parentSection, +1, next1) * 4 +
      scoreNeighborMatch(lineNumber, parentLines, parentSection, -2, prev2) +
      scoreNeighborMatch(lineNumber, parentLines, parentSection, +2, next2),
    distance: Math.abs(lineNumber - expectedLine),
  }));

  scored.sort((a, b) => b.score - a.score || a.distance - b.distance || a.lineNumber - b.lineNumber);
  return scored[0]?.lineNumber ?? null;
}

function narrowByNeighbor(
  candidates: number[],
  parentLines: string[],
  parentSection: PrivateSection,
  offset: number,
  expectedText: string | undefined,
) {
  if (expectedText === undefined) {
    return candidates;
  }

  const matched = candidates.filter((lineNumber) => {
    const neighborLine = lineNumber + offset;
    if (neighborLine < parentSection.startLine || neighborLine > parentSection.endLine) {
      return false;
    }
    return parentLines[neighborLine - 1] === expectedText;
  });

  return matched.length > 0 ? matched : candidates;
}

function scoreNeighborMatch(
  lineNumber: number,
  parentLines: string[],
  parentSection: PrivateSection,
  offset: number,
  expectedText: string | undefined,
) {
  if (expectedText === undefined) {
    return 0;
  }

  const neighborLine = lineNumber + offset;
  if (neighborLine < parentSection.startLine || neighborLine > parentSection.endLine) {
    return 0;
  }
  return parentLines[neighborLine - 1] === expectedText ? 1 : 0;
}

function toExpectedParentLine(
  currentIndex: number,
  currentSection: PrivateSection,
  parentSection: PrivateSection,
  currentCount: number,
) {
  const currentSpan = Math.max(currentCount - 1, 1);
  const ratio = currentIndex / currentSpan;
  const parentSpan = Math.max(parentSection.endLine - parentSection.startLine, 0);
  const projectedOffset = Math.round(parentSpan * ratio);
  const baseline = parentSection.startLine + projectedOffset;
  const lowerBound = parentSection.startLine;
  const upperBound = parentSection.endLine;
  return Math.max(lowerBound, Math.min(upperBound, baseline));
}

function collectReferencedPrNumbers(records: BlameRecord[]) {
  const numbers = new Set<number>();

  for (const record of records) {
    const prNumber = extractPrNumber(record.summary);
    if (prNumber !== null) {
      numbers.add(prNumber);
    }
  }

  return numbers;
}

function extractPrNumber(summary: string) {
  if (!summary) {
    return null;
  }

  const hashStyle = summary.match(/\(#(\d+)\)/);
  if (hashStyle) {
    return Number(hashStyle[1]);
  }

  const mergeStyle = summary.match(/pull request #(\d+)/i);
  if (mergeStyle) {
    return Number(mergeStyle[1]);
  }

  return null;
}

async function loadPullRequests(prNumbers: Set<number>) {
  const pullByNumber = new Map<number, PullRecord>();
  const sorted = [...prNumbers].sort((a, b) => a - b);

  for (const prNumber of sorted) {
    const filePath = path.join(PRS_DIR, `pr-${prNumber}.json`);
    try {
      const raw = await readFile(filePath, "utf8");
      const parsed = JSON.parse(raw) as {
        data?: {
          pull?: PullRecord;
        };
      };
      const pull = parsed?.data?.pull;
      if (!pull || typeof pull.number !== "number") {
        continue;
      }
      pullByNumber.set(prNumber, pull);
    } catch {
      // Ignore missing/invalid PR archives and fall back to commit metadata.
    }
  }

  console.log(`Loaded PR archives: requested=${prNumbers.size} found=${pullByNumber.size}`);
  return pullByNumber;
}

async function findLatestDomainContextPath() {
  const entries = await readdir(DOMAIN_CONTEXT_DIR, { withFileTypes: true });
  const candidates: { path: string; mtimeMs: number }[] = [];

  for (const entry of entries) {
    if (!entry.isFile()) {
      continue;
    }
    if (!/^domain-context-.*\.jsonl$/u.test(entry.name)) {
      continue;
    }
    const filePath = path.join(DOMAIN_CONTEXT_DIR, entry.name);
    const fileStat = await stat(filePath);
    candidates.push({
      path: filePath,
      mtimeMs: fileStat.mtimeMs,
    });
  }

  if (candidates.length === 0) {
    throw new Error(`No domain context runs found in ${DOMAIN_CONTEXT_DIR}`);
  }

  candidates.sort((a, b) => b.mtimeMs - a.mtimeMs || b.path.localeCompare(a.path));
  return candidates[0].path;
}

async function loadDomainContext(filePath: string) {
  const raw = await readFile(filePath, "utf8");
  const lines = splitLines(raw);
  const contextByDomain = new Map<string, DomainContextSummary>();
  let parseFailures = 0;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line) {
      continue;
    }

    let parsed: any;
    try {
      parsed = JSON.parse(line);
    } catch {
      const isLastLine = index === lines.length - 1;
      if (!isLastLine) {
        parseFailures += 1;
      }
      continue;
    }

    const domain = typeof parsed?.domain === "string" ? parsed.domain.toLowerCase() : "";
    if (!domain) {
      continue;
    }

    contextByDomain.set(domain, summarizeDomainContext(parsed));
  }

  console.log(
    `Loaded domain context: domains=${contextByDomain.size} parse_failures=${parseFailures} file=${path.relative(process.cwd(), filePath)}`,
  );

  return {
    contextByDomain,
    parseFailures,
  };
}

function summarizeDomainContext(record: any): DomainContextSummary {
  const attempt = pickSuccessfulAttempt(record);
  const final = attempt?.final;
  if (!final) {
    return { summary: "" };
  }
  const redirectDetail = summarizeRedirectDetail(attempt);

  const title = normalizeWhitespace(asString(final.title));
  const description = normalizeWhitespace(asString(final.description));
  const textExcerpt = normalizeWhitespace(asString(final.text_excerpt));
  const textSource = description || textExcerpt;
  let snippet = pickUsefulSnippet(textSource);
  if (title && snippet.startsWith(title)) {
    snippet = normalizeWhitespace(snippet.slice(title.length).replace(/^[\-:|. ]+/u, ""));
  }
  snippet = clip(snippet, MAX_CONTEXT_TEXT_CHARS);

  if (title && snippet) {
    return {
      summary: joinSummaryParts([
        `title = ${title}`,
        `text = ${snippet}`,
        redirectDetail,
      ]),
    };
  }
  if (title) {
    return {
      summary: joinSummaryParts([`title = ${title}`, redirectDetail]),
    };
  }
  if (snippet) {
    return {
      summary: joinSummaryParts([`text = ${snippet}`, redirectDetail]),
    };
  }

  const status = typeof final.status === "number" ? final.status : null;
  return {
    summary: joinSummaryParts([
      status === null ? "reachable" : `status = ${status}`,
      redirectDetail,
    ]),
  };
}

function pickSuccessfulAttempt(record: any) {
  if (record?.https?.final) {
    return record.https;
  }
  if (record?.http_fallback?.final) {
    return record.http_fallback;
  }
  return null;
}

function summarizeRedirectDetail(attempt: any) {
  const redirects = Array.isArray(attempt?.redirects) ? attempt.redirects : [];
  if (redirects.length === 0) {
    return "";
  }

  const hopLabel = redirects.length === 1 ? "hop" : "hops";
  const startHost = extractHost(asString(attempt?.start_url));
  const finalHost = extractHost(asString(attempt?.final?.url));

  if (startHost && finalHost && startHost !== finalHost) {
    return `redirected = ${redirects.length} ${hopLabel} (${startHost} -> ${finalHost})`;
  }
  return `redirected = ${redirects.length} ${hopLabel}`;
}

function extractHost(rawUrl: string) {
  if (!rawUrl) {
    return "";
  }
  try {
    return new URL(rawUrl).host;
  } catch {
    return "";
  }
}

function joinSummaryParts(parts: string[]) {
  return parts
    .map((part) => part.trim())
    .filter(Boolean)
    .join(", ");
}

function pickUsefulSnippet(text: string) {
  if (!text) {
    return "";
  }

  const normalized = normalizeWhitespace(text);
  if (!normalized) {
    return "";
  }

  const sentences = normalized
    .split(/(?<=[.!?])\s+/u)
    .map((sentence) => sentence.trim())
    .filter(Boolean);
  if (sentences.length === 0) {
    return normalized;
  }

  const startIndex = sentences.findIndex((sentence) => isUsefulSentence(sentence));
  if (startIndex === -1) {
    return normalized;
  }

  const selected: string[] = [];
  for (let index = startIndex; index < sentences.length; index += 1) {
    const sentence = sentences[index];
    if (selected.length > 0 && !isUsefulSentence(sentence)) {
      break;
    }
    selected.push(sentence);
    if (selected.length >= 3) {
      break;
    }
  }

  return selected.join(" ").trim();
}

function isUsefulSentence(sentence: string) {
  if (sentence.length < 16) {
    return false;
  }

  const lowered = sentence.toLowerCase();
  const navigationHints = [
    "open main menu",
    "products",
    "pricing",
    "docs",
    "customers",
    "blog",
    "status",
    "sign in",
    "get started",
  ];
  const hintCount = navigationHints.filter((hint) => lowered.includes(hint)).length;
  return hintCount <= 1;
}

function asString(value: unknown) {
  return typeof value === "string" ? value : "";
}

function renderEnrichedPrivateSection(
  privateLines: string[],
  blameRecords: BlameRecord[],
  pullByNumber: Map<number, PullRecord>,
  contextByDomain: Map<string, DomainContextSummary>,
) {
  const output: string[] = [];
  const attributions = blameRecords.map((blame) => buildAttribution(blame, pullByNumber));

  for (let index = 0; index < privateLines.length; ) {
    const attribution = attributions[index];
    let runEnd = index + 1;
    while (
      runEnd < attributions.length &&
      attributions[runEnd].key === attribution.key
    ) {
      runEnd += 1;
    }

    const runLength = runEnd - index;
    const isSingleBlankLineRun =
      runLength === 1 && !privateLines[index].trim();

    if (!isSingleBlankLineRun) {
      output.push(attribution.headerLine);
    }

    for (let lineIndex = index; lineIndex < runEnd; lineIndex += 1) {
      const enrichedLine = appendDomainContext(privateLines[lineIndex], contextByDomain);
      output.push(enrichedLine);
    }

    index = runEnd;
  }

  return output;
}

function buildAttribution(blame: BlameRecord, pullByNumber: Map<number, PullRecord>) {
  const prNumber = extractPrNumber(blame.summary);
  const pull = prNumber === null ? null : pullByNumber.get(prNumber) ?? null;

  if (pull) {
    const actor = normalizeActor(
      pull.user?.login ||
        emailHandle(blame.authorMail) ||
        blame.author,
    );
    const title = pull.title?.trim() || blame.summary || `PR #${pull.number}`;
    const body = normalizePrBody(pull.body ?? "");

    return {
      key: `pr:${pull.number}`,
      headerLine: `//! ${actor}: ${JSON.stringify(title)} ${JSON.stringify(body)}`,
    };
  }

  const actor = normalizeActor(emailHandle(blame.authorMail) || blame.author);
  const fallbackTitle = blame.summary || `commit ${blame.commit.slice(0, 12)}`;

  return {
    key: `commit:${blame.commit}`,
    headerLine: `//! ${actor}: ${JSON.stringify(fallbackTitle)} ${JSON.stringify(`commit ${blame.commit.slice(0, 12)}`)}`,
  };
}

function normalizePrBody(rawBody: string) {
  if (!rawBody.trim()) {
    return "";
  }

  const withoutComments = rawBody
    .replace(/\r\n/g, "\n")
    .replace(/<!--[\s\S]*?-->/gu, "")
    .replace(/^\s*[-*]\s*\[[ xX]\]\s+.*$/gmu, "")
    .replace(/^\s*Public Suffix List \(PSL\) Submission\s*$/gimu, "");

  const lines = withoutComments.split("\n").map((line) => line.replace(/\s+$/u, ""));
  const sections = new Map<string, string[]>();
  let activeSection: string | null = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();

    if (!trimmed) {
      if (activeSection) {
        sections.get(activeSection)?.push("");
      }
      continue;
    }

    if (/^[=~-]{3,}$/u.test(trimmed)) {
      continue;
    }

    const headingMatch = toCanonicalSection(trimmed);
    if (headingMatch) {
      activeSection = headingMatch;
      if (!sections.has(activeSection)) {
        sections.set(activeSection, []);
      }
      continue;
    }

    if (/^#+\s+/u.test(trimmed)) {
      activeSection = null;
      continue;
    }

    if (activeSection) {
      sections.get(activeSection)?.push(trimmed);
    }
  }

  const structuredParts: string[] = [];
  for (const heading of PRIMARY_BODY_SECTIONS) {
    const content = cleanupBodyLines(sections.get(heading) ?? []);
    if (!content) {
      continue;
    }
    structuredParts.push(`# ${heading}\n${content}`);
  }

  if (structuredParts.length > 0) {
    return clip(structuredParts.join("\n"), MAX_HEADER_BODY_CHARS);
  }

  const fallback = cleanupBodyLines(lines.map((line) => line.trim()));
  return clip(fallback, MAX_HEADER_BODY_CHARS);
}

function toCanonicalSection(rawHeading: string) {
  const markdownHeading = rawHeading.replace(/^#+\s+/u, "").trim();
  const normalized = markdownHeading
    .replace(/[ :]+$/u, "")
    .toLowerCase();

  return SECTION_ALIASES[normalized] ?? null;
}

function cleanupBodyLines(lines: string[]) {
  const trimmed = [...lines];
  while (trimmed.length > 0 && !trimmed[0].trim()) {
    trimmed.shift();
  }
  while (trimmed.length > 0 && !trimmed[trimmed.length - 1].trim()) {
    trimmed.pop();
  }

  const squashed: string[] = [];
  for (const line of trimmed) {
    if (!line.trim()) {
      if (squashed[squashed.length - 1] === "") {
        continue;
      }
      squashed.push("");
      continue;
    }
    squashed.push(line);
  }

  return squashed.join("\n").trim();
}

function normalizeActor(raw: string) {
  const normalized = raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/gu, "-")
    .replace(/^-+|-+$/gu, "");

  return normalized || "unknown";
}

function emailHandle(authorMail: string) {
  const trimmed = authorMail.replace(/^<|>$/gu, "").trim();
  const localPart = trimmed.split("@")[0] ?? "";
  if (!localPart) {
    return "";
  }

  const plusParts = localPart.split("+").filter(Boolean);
  if (plusParts.length > 1) {
    return plusParts[plusParts.length - 1];
  }

  return localPart;
}

function appendDomainContext(
  line: string,
  contextByDomain: Map<string, DomainContextSummary>,
) {
  const domains = extractDomainsFromLine(line);
  if (domains.length === 0) {
    return line;
  }

  const comments = domains
    .map((domain) => ({
      domain,
      summary: resolveDomainContextSummary(domain, contextByDomain),
    }))
    .filter((entry) => entry.summary.length > 0);

  if (comments.length === 0) {
    return line;
  }

  if (comments.length === 1) {
    if (domains.length > 1) {
      return `${line} // ${comments[0].domain}: ${comments[0].summary}`;
    }
    return `${line} // ${comments[0].summary}`;
  }

  return `${line} // ${comments.map((item) => `${item.domain}: ${item.summary}`).join("; ")}`;
}

function resolveDomainContextSummary(
  domain: string,
  contextByDomain: Map<string, DomainContextSummary>,
) {
  const direct = contextByDomain.get(domain)?.summary.trim() ?? "";
  if (direct) {
    return direct;
  }

  if (domain.startsWith("www.")) {
    const withoutWww = domain.slice(4);
    const fallback = contextByDomain.get(withoutWww)?.summary.trim() ?? "";
    if (fallback) {
      return fallback;
    }
  } else {
    const withWww = `www.${domain}`;
    const fallback = contextByDomain.get(withWww)?.summary.trim() ?? "";
    if (fallback) {
      return fallback;
    }
  }

  return "";
}

function extractDomainsFromLine(line: string) {
  const domains: string[] = [];
  const seen = new Set<string>();

  DOMAIN_EXTRACTOR.lastIndex = 0;
  for (const match of line.matchAll(DOMAIN_EXTRACTOR)) {
    const extracted = match[1] ?? match[2] ?? match[3] ?? match[4] ?? match[5] ?? "";
    const normalized = normalizeDomain(extracted);
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    domains.push(normalized);
  }

  return removeBareWhenWwwExists(domains);
}

function normalizeDomain(raw: string) {
  const domain = raw.trim().toLowerCase();
  if (!isLikelyDomain(domain)) {
    return null;
  }
  return domain;
}

function isLikelyDomain(domain: string) {
  if (!domain) {
    return false;
  }

  const labels = domain.split(".");
  if (labels.length < 2) {
    return false;
  }

  if (!labels.every((label) => LABEL_REGEX.test(label))) {
    return false;
  }

  if (!labels.some((label) => HAS_LETTER_PATTERN.test(label))) {
    return false;
  }

  return true;
}

function removeBareWhenWwwExists(domains: string[]) {
  const domainSet = new Set(domains);
  return domains.filter((domain) => {
    if (domain.startsWith("www.")) {
      return true;
    }
    return !domainSet.has(`www.${domain}`);
  });
}

function normalizeWhitespace(value: string) {
  return value.replace(/\s+/gu, " ").trim();
}

function clip(value: string, maxLength: number) {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, maxLength)}...`;
}

function runGitInPsl(args: string[]) {
  const result = spawnSync("git", args, {
    cwd: PSL_DIR,
    encoding: "utf8",
    maxBuffer: MAX_GIT_BUFFER_BYTES,
  });

  if (result.status === 0 && typeof result.stdout === "string") {
    return result.stdout;
  }

  const stderr = typeof result.stderr === "string" ? result.stderr.trim() : "";
  const spawnError = result.error instanceof Error ? result.error.message : "";
  throw new Error(
    `git ${args.join(" ")} failed (status=${result.status ?? "null"}): ${stderr || spawnError || "unknown error"}`,
  );
}

if (isDirectRun(import.meta.url)) {
  const summary = await buildEnrichedPrivatePslOutput();
  console.log(JSON.stringify(summary, null, 2));
}

function isDirectRun(moduleUrl: string) {
  const entryPath = process.argv[1];
  if (!entryPath) {
    return false;
  }
  return moduleUrl === pathToFileURL(path.resolve(entryPath)).href;
}
