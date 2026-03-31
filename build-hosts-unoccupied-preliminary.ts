import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  createReadStream,
  createWriteStream,
  type ReadStream,
  type WriteStream,
} from "node:fs";
import { mkdir, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { createInterface, type Interface } from "node:readline";
import { pathToFileURL } from "node:url";

const HOSTS_FILE = path.resolve("data", "hosts.txt");
const ZONES_DIR = path.resolve("data", "zones");
const OUTPUT_FILE = path.resolve("data", "hosts_unoccupied_preliminary.txt");
const TEMP_DIR = path.resolve("data", "hosts-unoccupied-preliminary");

const HOSTS_READ_HIGH_WATER_MARK = 1024 * 1024;
const ZONE_READ_HIGH_WATER_MARK = 1024 * 1024;
const HOST_PROGRESS_EVERY = 5_000_000;
const ZONE_PROGRESS_EVERY = 25;
const SORT_FINAL_OUTPUT = true;
const ZONE_FILTER: ReadonlySet<string> | null = null;
const APP_SYNTHETIC_LABEL_MIN_LENGTH = 24;
const APP_SYNTHETIC_LABEL_REGEX = /^[a-z0-9]+$/;
const FIVE_DIGIT_LABEL_REGEX = /^[0-9]{5}$/;

type BuildOptions = {
  hostsFilePath?: string;
  zonesDirPath?: string;
  outputFilePath?: string;
  tempDirPath?: string;
  zoneFilter?: ReadonlySet<string> | null;
};

type BuildSummary = {
  outputPath: string;
  tempDirPath: string;
  zonesAvailable: number;
  zonesCompared: number;
  zonesWithResults: number;
  hostsScanned: number;
  relevantZoneHostsScanned: number;
  crawledEffectiveDomainsRaw: number;
  crawledEffectiveDomainsUnique: number;
  liveDomainsRaw: number;
  liveDomainsUnique: number;
  unoccupiedDomains: number;
};

type HostReader = {
  iterator: AsyncIterator<string>;
  lineReader: Interface;
  stream: ReadStream;
  hostsScanned: number;
  previousHost: string;
};

type SortedReader = {
  iterator: AsyncIterator<string>;
  stream: ReadStream;
  linesRead: number;
};

type RawZoneCrawlSummary = {
  nextHost: string | null;
  hostsConsumed: number;
  rawDomainsWritten: number;
};

type SubtractionSummary = {
  leftLinesRead: number;
  rightLinesRead: number;
  outputLinesWritten: number;
};

export async function buildHostsUnoccupiedPreliminary(
  options: BuildOptions = {},
): Promise<BuildSummary> {
  const hostsFilePath = options.hostsFilePath ?? HOSTS_FILE;
  const zonesDirPath = options.zonesDirPath ?? ZONES_DIR;
  const outputFilePath = options.outputFilePath ?? OUTPUT_FILE;
  const tempDirPath = options.tempDirPath ?? TEMP_DIR;
  const zoneFilter = options.zoneFilter ?? ZONE_FILTER;
  const tempPaths = getTempPaths(tempDirPath);

  const zoneFiles = await loadZoneFiles(zonesDirPath, zoneFilter);
  const relevantZones = [...zoneFiles.keys()];
  const lastRelevantZone = relevantZones[relevantZones.length - 1] ?? "";

  await rm(tempDirPath, { recursive: true, force: true });
  await mkdir(tempDirPath, { recursive: true });
  await mkdir(path.dirname(outputFilePath), { recursive: true });

  const output = createWriteStream(outputFilePath, {
    flags: "w",
    encoding: "utf8",
  });
  const hosts = createHostReader(hostsFilePath);

  console.log(
    `Loaded zone files: count=${relevantZones.length} dir=${path.relative(process.cwd(), zonesDirPath)}`,
  );
  console.log(
    `Building unoccupied domains from ${path.relative(process.cwd(), hostsFilePath)} -> ${path.relative(process.cwd(), outputFilePath)}`,
  );

  let currentHost = await readNextNormalizedHost(hosts);
  let zonesCompared = 0;
  let zonesWithResults = 0;
  let relevantZoneHostsScanned = 0;
  let crawledEffectiveDomainsRaw = 0;
  let crawledEffectiveDomainsUnique = 0;
  let liveDomainsRaw = 0;
  let liveDomainsUnique = 0;
  let unoccupiedDomains = 0;

  try {
    while (currentHost !== null) {
      const currentZone = getLeadingLabel(currentHost);
      if (!currentZone) {
        currentHost = await readNextNormalizedHost(hosts);
        continue;
      }

      if (lastRelevantZone && compareAscii(currentZone, lastRelevantZone) > 0) {
        break;
      }

      const zoneFilePath = zoneFiles.get(currentZone);
      if (!zoneFilePath) {
        currentHost = await skipZoneHosts(hosts, currentZone);
        continue;
      }

      zonesCompared += 1;

      const crawledRawSummary = await writeCrawledDomainsForZone({
        zone: currentZone,
        firstHost: currentHost,
        hosts,
        crawledRawPath: tempPaths.crawledRawPath,
      });
      currentHost = crawledRawSummary.nextHost;
      relevantZoneHostsScanned += crawledRawSummary.hostsConsumed;
      crawledEffectiveDomainsRaw += crawledRawSummary.rawDomainsWritten;

      const liveRawWritten = await writeLiveDomainsForZone({
        zone: currentZone,
        zoneFilePath,
        liveRawPath: tempPaths.liveRawPath,
      });
      liveDomainsRaw += liveRawWritten;

      await sortUniqueFile(
        tempPaths.crawledRawPath,
        tempPaths.crawledUniquePath,
      );
      await sortUniqueFile(tempPaths.liveRawPath, tempPaths.liveUniquePath);

      const subtractionSummary = await appendSortedDifference({
        leftPath: tempPaths.crawledUniquePath,
        rightPath: tempPaths.liveUniquePath,
        output,
      });

      crawledEffectiveDomainsUnique += subtractionSummary.leftLinesRead;
      liveDomainsUnique += subtractionSummary.rightLinesRead;
      unoccupiedDomains += subtractionSummary.outputLinesWritten;

      if (subtractionSummary.outputLinesWritten > 0) {
        zonesWithResults += 1;
      }

      console.log(
        `Zone ${currentZone}: crawled_raw=${crawledRawSummary.rawDomainsWritten} crawled_unique=${subtractionSummary.leftLinesRead} live_raw=${liveRawWritten} live_unique=${subtractionSummary.rightLinesRead} unoccupied=${subtractionSummary.outputLinesWritten}`,
      );

      if (zonesCompared % ZONE_PROGRESS_EVERY === 0 || currentHost === null) {
        console.log(
          `Zone progress: compared=${zonesCompared}/${relevantZones.length} zones_with_results=${zonesWithResults} hosts_scanned=${hosts.hostsScanned} unoccupied=${unoccupiedDomains}`,
        );
      }
    }
  } finally {
    closeLineReader(hosts.lineReader, hosts.stream);
    output.end();
    await once(output, "finish");
  }

  console.log(
    `Wrote ${unoccupiedDomains} domains to ${path.relative(process.cwd(), outputFilePath)}`,
  );

  return {
    outputPath: outputFilePath,
    tempDirPath,
    zonesAvailable: relevantZones.length,
    zonesCompared,
    zonesWithResults,
    hostsScanned: hosts.hostsScanned,
    relevantZoneHostsScanned,
    crawledEffectiveDomainsRaw,
    crawledEffectiveDomainsUnique,
    liveDomainsRaw,
    liveDomainsUnique,
    unoccupiedDomains,
  };
}

function getTempPaths(tempDirPath: string) {
  return {
    crawledRawPath: path.join(tempDirPath, "crawled-raw.txt"),
    crawledUniquePath: path.join(tempDirPath, "crawled-unique.txt"),
    liveRawPath: path.join(tempDirPath, "live-raw.txt"),
    liveUniquePath: path.join(tempDirPath, "live-unique.txt"),
  };
}

async function loadZoneFiles(
  zonesDirPath: string,
  zoneFilter: ReadonlySet<string> | null,
) {
  const entries = await readdir(zonesDirPath, { withFileTypes: true });
  const zoneFiles = new Map<string, string>();

  for (const entry of entries) {
    if (!entry.isFile()) {
      continue;
    }
    if (!entry.name.endsWith(".txt")) {
      continue;
    }

    const zone = entry.name.slice(0, -4).toLowerCase();
    if (zoneFilter && !zoneFilter.has(zone)) {
      continue;
    }

    zoneFiles.set(zone, path.join(zonesDirPath, entry.name));
  }

  return new Map(
    [...zoneFiles.entries()].sort(([left], [right]) =>
      compareAscii(left, right),
    ),
  );
}

function createHostReader(hostsFilePath: string): HostReader {
  const stream = createReadStream(hostsFilePath, {
    encoding: "utf8",
    highWaterMark: HOSTS_READ_HIGH_WATER_MARK,
  });
  const lineReader = createInterface({
    input: stream,
    crlfDelay: Infinity,
  });

  return {
    iterator: lineReader[Symbol.asyncIterator](),
    lineReader,
    stream,
    hostsScanned: 0,
    previousHost: "",
  };
}

async function readNextNormalizedHost(hosts: HostReader) {
  while (true) {
    const { value, done } = await hosts.iterator.next();
    if (done) {
      return null;
    }

    hosts.hostsScanned += 1;
    if (hosts.hostsScanned % HOST_PROGRESS_EVERY === 0) {
      console.log(`Host progress: scanned=${hosts.hostsScanned}`);
    }

    const host = normalizeReversedHostEntry(value);
    if (!host) {
      continue;
    }

    if (hosts.previousHost && compareAscii(host, hosts.previousHost) < 0) {
      throw new Error(
        `Common Crawl hosts file is not sorted at line=${hosts.hostsScanned}: ${host} < ${hosts.previousHost}`,
      );
    }

    hosts.previousHost = host;
    return host;
  }
}

async function skipZoneHosts(hosts: HostReader, zone: string) {
  let currentHost = await readNextNormalizedHost(hosts);

  while (currentHost !== null && getLeadingLabel(currentHost) === zone) {
    currentHost = await readNextNormalizedHost(hosts);
  }

  return currentHost;
}

async function writeCrawledDomainsForZone(options: {
  zone: string;
  firstHost: string;
  hosts: HostReader;
  crawledRawPath: string;
}): Promise<RawZoneCrawlSummary> {
  const { zone, firstHost, hosts, crawledRawPath } = options;
  const output = createWriteStream(crawledRawPath, {
    flags: "w",
    encoding: "utf8",
  });

  let currentHost: string | null = firstHost;
  let hostsConsumed = 0;
  let rawDomainsWritten = 0;

  try {
    while (currentHost !== null && getLeadingLabel(currentHost) === zone) {
      const domain = toEffectiveDomain(currentHost, zone);
      hostsConsumed += 1;
      if (domain) {
        await writeLine(output, domain);
        rawDomainsWritten += 1;
      }
      currentHost = await readNextNormalizedHost(hosts);
    }
  } finally {
    output.end();
    await once(output, "finish");
  }

  return {
    nextHost: currentHost,
    hostsConsumed,
    rawDomainsWritten,
  };
}

async function writeLiveDomainsForZone(options: {
  zone: string;
  zoneFilePath: string;
  liveRawPath: string;
}) {
  const { zone, zoneFilePath, liveRawPath } = options;
  const output = createWriteStream(liveRawPath, {
    flags: "w",
    encoding: "utf8",
  });
  const stream = createReadStream(zoneFilePath, {
    encoding: "utf8",
    highWaterMark: ZONE_READ_HIGH_WATER_MARK,
  });

  let rawDomainsWritten = 0;

  try {
    for await (const line of iterateLines(stream)) {
      const domain = extractLiveDomainFromZoneRecord(line, zone);
      if (!domain) {
        continue;
      }
      await writeLine(output, domain);
      rawDomainsWritten += 1;
    }
  } finally {
    output.end();
    await once(output, "finish");
  }

  return rawDomainsWritten;
}

async function* iterateLines(stream: ReadStream) {
  let carry = "";

  for await (const chunk of stream) {
    carry += chunk;

    while (true) {
      const newlineIndex = carry.indexOf("\n");
      if (newlineIndex === -1) {
        break;
      }

      let line = carry.slice(0, newlineIndex);
      carry = carry.slice(newlineIndex + 1);
      if (line.endsWith("\r")) {
        line = line.slice(0, -1);
      }
      yield line;
    }
  }

  if (!carry) {
    return;
  }

  if (carry.endsWith("\r")) {
    carry = carry.slice(0, -1);
  }
  yield carry;
}

function createSortedReader(filePath: string): SortedReader {
  const stream = createReadStream(filePath, {
    encoding: "utf8",
    highWaterMark: ZONE_READ_HIGH_WATER_MARK,
  });

  return {
    iterator: iterateLines(stream)[Symbol.asyncIterator](),
    stream,
    linesRead: 0,
  };
}

async function readNextSortedLine(reader: SortedReader) {
  while (true) {
    const { value, done } = await reader.iterator.next();
    if (done) {
      return null;
    }

    const line = value.trim();
    if (!line) {
      continue;
    }

    reader.linesRead += 1;
    return line;
  }
}

async function appendSortedDifference(options: {
  leftPath: string;
  rightPath: string;
  output: WriteStream;
}): Promise<SubtractionSummary> {
  const { leftPath, rightPath, output } = options;

  const left = createSortedReader(leftPath);
  const right = createSortedReader(rightPath);

  let outputLinesWritten = 0;
  let leftLine = await readNextSortedLine(left);
  let rightLine = await readNextSortedLine(right);

  try {
    while (leftLine !== null) {
      if (rightLine === null) {
        await writeLine(output, leftLine);
        outputLinesWritten += 1;
        leftLine = await readNextSortedLine(left);
        continue;
      }

      const comparison = compareAscii(leftLine, rightLine);
      if (comparison < 0) {
        await writeLine(output, leftLine);
        outputLinesWritten += 1;
        leftLine = await readNextSortedLine(left);
        continue;
      }

      if (comparison === 0) {
        leftLine = await readNextSortedLine(left);
        rightLine = await readNextSortedLine(right);
        continue;
      }

      rightLine = await readNextSortedLine(right);
    }
  } finally {
    left.stream.destroy();
    right.stream.destroy();
  }

  return {
    leftLinesRead: left.linesRead,
    rightLinesRead: right.linesRead,
    outputLinesWritten,
  };
}

async function sortUniqueFile(inputPath: string, outputPath: string) {
  await new Promise<void>((resolve, reject) => {
    const child = spawn("sort", ["-u", "-o", outputPath, inputPath], {
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        ...process.env,
        LC_ALL: "C",
      },
    });

    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(
        new Error(
          `sort failed for ${inputPath} (code=${String(code)}, signal=${String(signal)})`,
        ),
      );
    });
  });
}

function extractLiveDomainFromZoneRecord(line: string, zone: string) {
  const owner = readToken(line, 0);
  const type = readToken(line, 3)?.toLowerCase() ?? "";

  if (!owner || type !== "ns") {
    return "";
  }

  const normalizedOwner = owner.endsWith(".")
    ? owner.slice(0, -1).toLowerCase()
    : owner.toLowerCase();

  if (normalizedOwner === zone) {
    return "";
  }
  if (!normalizedOwner.endsWith(`.${zone}`)) {
    return "";
  }

  const prefix = normalizedOwner.slice(0, -(zone.length + 1));
  if (!prefix || prefix.includes(".")) {
    return "";
  }

  return normalizedOwner;
}

function readToken(line: string, tokenIndex: number) {
  let index = 0;
  let currentToken = 0;

  while (index < line.length) {
    while (index < line.length && isWhitespace(line.charCodeAt(index))) {
      index += 1;
    }
    if (index >= line.length) {
      return "";
    }

    const start = index;
    while (index < line.length && !isWhitespace(line.charCodeAt(index))) {
      index += 1;
    }

    if (currentToken === tokenIndex) {
      return line.slice(start, index);
    }

    currentToken += 1;
  }

  return "";
}

function isWhitespace(charCode: number) {
  return (
    charCode === 9 || charCode === 10 || charCode === 13 || charCode === 32
  );
}

function normalizeReversedHostEntry(rawHost: string) {
  const trimmed = rawHost.trim().toLowerCase();
  if (!trimmed) {
    return "";
  }

  const withoutTrailingDot = trimmed.endsWith(".")
    ? trimmed.slice(0, -1)
    : trimmed;
  if (!withoutTrailingDot.includes(".")) {
    return "";
  }

  return withoutTrailingDot;
}

function getLeadingLabel(reversedHost: string) {
  const dotIndex = reversedHost.indexOf(".");
  if (dotIndex === -1) {
    return "";
  }
  return reversedHost.slice(0, dotIndex);
}

function toEffectiveDomain(reversedHost: string, zone: string) {
  const firstDot = reversedHost.indexOf(".");
  if (firstDot === -1) {
    return "";
  }

  const secondDot = reversedHost.indexOf(".", firstDot + 1);
  const secondLabel =
    secondDot === -1
      ? reversedHost.slice(firstDot + 1)
      : reversedHost.slice(firstDot + 1, secondDot);

  if (!secondLabel) {
    return "";
  }
  if (shouldIgnoreEffectiveDomain(zone, secondLabel)) {
    return "";
  }

  return `${secondLabel}.${zone}`;
}

function shouldIgnoreEffectiveDomain(zone: string, label: string) {
  if (FIVE_DIGIT_LABEL_REGEX.test(label)) {
    return true;
  }

  if (zone !== "app") {
    return false;
  }
  if (label.length < APP_SYNTHETIC_LABEL_MIN_LENGTH) {
    return false;
  }
  if (!APP_SYNTHETIC_LABEL_REGEX.test(label)) {
    return false;
  }
  if (!/[a-z]/.test(label) || !/\d/.test(label)) {
    return false;
  }

  return true;
}

async function writeLine(output: WriteStream, line: string) {
  if (output.write(`${line}\n`)) {
    return;
  }

  await once(output, "drain");
}

function compareAscii(left: string, right: string) {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function closeLineReader(lineReader: Interface, stream: ReadStream) {
  lineReader.close();
  stream.destroy();
}

async function runAsScript() {
  const summary = await buildHostsUnoccupiedPreliminary();
  console.log(JSON.stringify(summary, null, 2));
}

const isDirectRun = process.argv[1]
  ? import.meta.url === pathToFileURL(process.argv[1]).href
  : false;

if (isDirectRun) {
  runAsScript().catch((error: unknown) => {
    if (error instanceof Error) {
      console.error(error.stack ?? error.message);
    } else {
      console.error(error);
    }
    process.exitCode = 1;
  });
}
