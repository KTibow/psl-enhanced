import { appendFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import tls from "node:tls";
import { domainToASCII, pathToFileURL } from "node:url";
import { privatePslDomains } from "./private-psl.ts";

const OUTPUT_DIR = path.resolve("data", "domain-context");
const CONCURRENCY = 5;
const REQUEST_TIMEOUT_MS = 15_000;
const TLS_TIMEOUT_MS = 12_000;
const MAX_REDIRECTS = 10;
const MAX_BODY_BYTES = 250_000;
const MAX_TEXT_CHARS = 3_000;
const PROGRESS_EVERY = 25;
const USER_AGENT = "psl-domain-context/1.0";
const MAX_DOMAINS = Number.POSITIVE_INFINITY;
const ACCEPT_HEADER =
  "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5";

type StructuredError = {
  name: string;
  message: string;
  code?: string | number;
  errno?: string | number;
  syscall?: string;
  cause?: StructuredError;
};

type TlsProbe = {
  ok: boolean;
  authorized?: boolean;
  authorization_error?: string | null;
  cert?: {
    subject_cn: string | null;
    issuer_cn: string | null;
    subject_alt_names: string[];
    valid_from: string | null;
    valid_to: string | null;
  };
  hostname_match_error?: string | null;
  certificate_likely_for?: string | null;
  error?: StructuredError;
};

type RedirectHop = {
  from: string;
  status: number;
  status_text: string;
  location: string | null;
  to: string | null;
};

type FinalPage = {
  url: string;
  status: number;
  status_text: string;
  content_type: string | null;
  content_length_header: string | null;
  body_bytes: number;
  body_truncated: boolean;
  title: string | null;
  description: string | null;
  text_excerpt: string | null;
};

type FetchAttempt = {
  start_url: string;
  redirects: RedirectHop[];
  final?: FinalPage;
  error?: StructuredError;
};

type DomainContextRecord = {
  domain: string;
  network_domain: string;
  started_at: string;
  finished_at: string;
  tls_443: TlsProbe;
  https: FetchAttempt;
  http_fallback?: FetchAttempt;
  selected_protocol: "https" | "http" | null;
};

type RunOptions = {
  domains?: string[];
  maxDomains?: number;
  outputPath?: string;
  concurrency?: number;
};

export async function scrapePrivatePslDomainContext(options: RunOptions = {}) {
  const domains = [...(options.domains ?? [...privatePslDomains].sort())];
  const maxDomains = options.maxDomains ?? MAX_DOMAINS;
  const targetDomains = domains.slice(
    0,
    Number.isFinite(maxDomains) ? maxDomains : undefined,
  );
  const outputPath = options.outputPath ?? defaultOutputPath();
  const concurrency = Math.max(1, options.concurrency ?? CONCURRENCY);

  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, "", "utf8");

  const writer = createJsonlWriter(outputPath);
  const stats = {
    completed: 0,
    successes: 0,
    failures: 0,
  };

  console.log(`Scraping ${targetDomains.length} domains -> ${outputPath}`);

  await runWithConcurrency(targetDomains, concurrency, async (domain) => {
    const result = await scrapeDomain(domain);
    await writer.write(result);

    stats.completed += 1;
    if (result.selected_protocol) {
      stats.successes += 1;
    } else {
      stats.failures += 1;
    }

    if (
      stats.completed % PROGRESS_EVERY === 0 ||
      stats.completed === targetDomains.length
    ) {
      console.log(
        `progress completed=${stats.completed}/${targetDomains.length} successes=${stats.successes} failures=${stats.failures}`,
      );
    }
  });

  await writer.flush();

  console.log(
    `Done. completed=${stats.completed} successes=${stats.successes} failures=${stats.failures}`,
  );

  return {
    outputPath,
    domains: targetDomains.length,
    ...stats,
  };
}

async function scrapeDomain(domain: string): Promise<DomainContextRecord> {
  const startedAt = new Date().toISOString();
  const networkDomain = domainToASCII(domain) || domain;

  const tlsProbe = await probeTls(networkDomain);
  const httpsAttempt = await fetchWithRedirects(`https://${networkDomain}`);
  const httpFallback = httpsAttempt.final
    ? undefined
    : await fetchWithRedirects(`http://${networkDomain}`);
  const selectedProtocol = httpsAttempt.final
    ? "https"
    : httpFallback?.final
      ? "http"
      : null;

  return {
    domain,
    network_domain: networkDomain,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    tls_443: tlsProbe,
    https: httpsAttempt,
    http_fallback: httpFallback,
    selected_protocol: selectedProtocol,
  };
}

async function probeTls(networkDomain: string): Promise<TlsProbe> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: networkDomain,
      port: 443,
      servername: networkDomain,
      rejectUnauthorized: false,
      timeout: TLS_TIMEOUT_MS,
      ALPNProtocols: ["http/1.1"],
    });

    let done = false;
    const finish = (result: TlsProbe) => {
      if (done) {
        return;
      }
      done = true;
      socket.destroy();
      resolve(result);
    };

    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      const altNames = parseSubjectAltName(
        typeof cert.subjectaltname === "string" ? cert.subjectaltname : "",
      );
      const hostnameError = tls.checkServerIdentity(networkDomain, cert);

      finish({
        ok: true,
        authorized: socket.authorized,
        authorization_error: socket.authorizationError ?? null,
        cert: {
          subject_cn: cert.subject?.CN ?? null,
          issuer_cn: cert.issuer?.CN ?? null,
          subject_alt_names: altNames,
          valid_from: cert.valid_from ?? null,
          valid_to: cert.valid_to ?? null,
        },
        hostname_match_error: hostnameError?.message ?? null,
        certificate_likely_for: hostnameError
          ? pickLikelyCertificateName(altNames, cert.subject?.CN ?? null)
          : null,
      });
    });

    socket.once("timeout", () => {
      finish({
        ok: false,
        error: {
          name: "TimeoutError",
          message: `TLS handshake timed out after ${TLS_TIMEOUT_MS}ms`,
        },
      });
    });

    socket.once("error", (error) => {
      finish({
        ok: false,
        error: serializeError(error),
      });
    });
  });
}

function parseSubjectAltName(raw: string) {
  if (!raw) {
    return [];
  }

  return raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) =>
      part.replace(/^DNS:/iu, "").replace(/^IP Address:/iu, "ip:"),
    );
}

function pickLikelyCertificateName(altNames: string[], cn: string | null) {
  return altNames.find((name) => !name.startsWith("*.")) ?? altNames[0] ?? cn;
}

async function fetchWithRedirects(startUrl: string): Promise<FetchAttempt> {
  const redirects: RedirectHop[] = [];
  let currentUrl = startUrl;

  for (let i = 0; i <= MAX_REDIRECTS; i += 1) {
    let response: Response;

    try {
      response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: {
          "user-agent": USER_AGENT,
          accept: ACCEPT_HEADER,
        },
      });
    } catch (error) {
      return {
        start_url: startUrl,
        redirects,
        error: serializeError(error),
      };
    }

    const location = response.headers.get("location");
    if (isRedirectStatus(response.status) && location) {
      let nextUrl: string;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch (error) {
        redirects.push({
          from: currentUrl,
          status: response.status,
          status_text: response.statusText,
          location,
          to: null,
        });
        return {
          start_url: startUrl,
          redirects,
          error: serializeError(error),
        };
      }

      redirects.push({
        from: currentUrl,
        status: response.status,
        status_text: response.statusText,
        location,
        to: nextUrl,
      });
      currentUrl = nextUrl;
      continue;
    }

    const final = await toFinalPage(currentUrl, response);
    return {
      start_url: startUrl,
      redirects,
      final,
    };
  }

  return {
    start_url: startUrl,
    redirects,
    error: {
      name: "RedirectLimitError",
      message: `Exceeded max redirects (${MAX_REDIRECTS})`,
    },
  };
}

function isRedirectStatus(status: number) {
  return status >= 300 && status < 400;
}

async function toFinalPage(
  url: string,
  response: Response,
): Promise<FinalPage> {
  const contentType = response.headers.get("content-type");
  const body = await readBodyText(response, contentType);
  const parsed = extractPageSignals(body.text, contentType);

  return {
    url,
    status: response.status,
    status_text: response.statusText,
    content_type: contentType,
    content_length_header: response.headers.get("content-length"),
    body_bytes: body.bytes,
    body_truncated: body.truncated,
    title: parsed.title,
    description: parsed.description,
    text_excerpt: parsed.textExcerpt,
  };
}

async function readBodyText(response: Response, contentType: string | null) {
  const reader = response.body?.getReader();
  if (!reader) {
    return { text: "", bytes: 0, truncated: false };
  }

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let truncated = false;

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    if (!value) {
      continue;
    }

    const remaining = MAX_BODY_BYTES - totalBytes;
    if (remaining <= 0) {
      truncated = true;
      break;
    }

    if (value.byteLength > remaining) {
      chunks.push(value.subarray(0, remaining));
      totalBytes += remaining;
      truncated = true;
      break;
    }

    chunks.push(value);
    totalBytes += value.byteLength;
  }

  if (truncated) {
    try {
      await reader.cancel();
    } catch {
      // Ignore cancellation errors.
    }
  }

  const merged = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
  const text = decodeBody(merged, contentType);

  return {
    text,
    bytes: totalBytes,
    truncated,
  };
}

function decodeBody(buffer: Buffer, contentType: string | null) {
  const declared = contentType
    ?.match(/charset\s*=\s*["']?([^;"'\s]+)/iu)?.[1]
    ?.trim()
    .toLowerCase();
  const candidate = declared || "utf-8";

  try {
    return new TextDecoder(candidate).decode(buffer);
  } catch {
    return new TextDecoder("utf-8").decode(buffer);
  }
}

function extractPageSignals(rawBody: string, contentType: string | null) {
  const isHtml =
    /text\/html|application\/xhtml\+xml/iu.test(contentType ?? "") ||
    /<!doctype html|<html|<title/iu.test(rawBody);

  if (!isHtml) {
    const cleaned = normalizeWhitespace(stripControls(rawBody));
    return {
      title: null,
      description: null,
      textExcerpt: cleaned ? clip(cleaned, MAX_TEXT_CHARS) : null,
    };
  }

  const titleMatch = rawBody.match(/<title\b[^>]*>([\s\S]*?)<\/title>/iu);
  const title = titleMatch
    ? normalizeWhitespace(decodeHtmlEntities(titleMatch[1]))
    : null;
  const description =
    findMetaContent(rawBody, "description") ??
    findMetaContent(rawBody, "og:description") ??
    findMetaContent(rawBody, "twitter:description");

  const text = htmlToText(rawBody);

  return {
    title: title || null,
    description: description || null,
    textExcerpt: text ? clip(text, MAX_TEXT_CHARS) : null,
  };
}

function findMetaContent(html: string, key: string) {
  const tags = html.match(/<meta\b[^>]*>/giu) ?? [];
  const needle = key.toLowerCase();

  for (const tag of tags) {
    const name = (
      readAttribute(tag, "name") ??
      readAttribute(tag, "property") ??
      ""
    ).toLowerCase();
    if (name !== needle) {
      continue;
    }

    const content = readAttribute(tag, "content");
    if (content) {
      return normalizeWhitespace(decodeHtmlEntities(content));
    }
  }

  return null;
}

function readAttribute(tag: string, attribute: string) {
  const pattern = new RegExp(
    `\\b${attribute}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>\\x60]+))`,
    "iu",
  );
  const match = tag.match(pattern);
  if (!match) {
    return null;
  }
  return match[1] ?? match[2] ?? match[3] ?? null;
}

function htmlToText(html: string) {
  const withoutScripts = html
    .replace(/<script\b[\s\S]*?<\/script>/giu, " ")
    .replace(/<style\b[\s\S]*?<\/style>/giu, " ")
    .replace(/<noscript\b[\s\S]*?<\/noscript>/giu, " ");

  const withBreaks = withoutScripts.replace(
    /<\/(p|div|li|h[1-6]|br|tr|section|article|main|header|footer)>/giu,
    "\n",
  );
  const withoutTags = withBreaks.replace(/<[^>]+>/g, " ");
  const decoded = decodeHtmlEntities(withoutTags);
  return clip(normalizeWhitespace(stripControls(decoded)), MAX_TEXT_CHARS);
}

function decodeHtmlEntities(value: string) {
  return value.replace(
    /&(#x?[0-9a-f]+|[a-z][a-z0-9]+);/giu,
    (_, rawEntity: string) => {
      if (rawEntity.startsWith("#x") || rawEntity.startsWith("#X")) {
        const parsed = Number.parseInt(rawEntity.slice(2), 16);
        return Number.isNaN(parsed)
          ? `&${rawEntity};`
          : String.fromCodePoint(parsed);
      }

      if (rawEntity.startsWith("#")) {
        const parsed = Number.parseInt(rawEntity.slice(1), 10);
        return Number.isNaN(parsed)
          ? `&${rawEntity};`
          : String.fromCodePoint(parsed);
      }

      const named = NAMED_ENTITIES[rawEntity.toLowerCase()];
      return named ?? `&${rawEntity};`;
    },
  );
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  copy: "©",
  reg: "®",
  trade: "™",
};

function stripControls(value: string) {
  return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ");
}

function normalizeWhitespace(value: string) {
  return value.replace(/\s+/g, " ").trim();
}

function clip(value: string, maxChars: number) {
  if (value.length <= maxChars) {
    return value;
  }
  return `${value.slice(0, maxChars)}...`;
}

function serializeError(error: unknown, depth = 0): StructuredError {
  if (error instanceof Error) {
    const withCode = error as Error & {
      code?: string | number;
      errno?: string | number;
      syscall?: string;
      cause?: unknown;
    };

    const serialized: StructuredError = {
      name: error.name,
      message: error.message,
    };

    if (withCode.code !== undefined) {
      serialized.code = withCode.code;
    }
    if (withCode.errno !== undefined) {
      serialized.errno = withCode.errno;
    }
    if (withCode.syscall !== undefined) {
      serialized.syscall = withCode.syscall;
    }
    if (depth < 2 && withCode.cause) {
      serialized.cause = serializeError(withCode.cause, depth + 1);
    }

    return serialized;
  }

  return {
    name: "NonError",
    message: String(error),
  };
}

function defaultOutputPath() {
  const runId = new Date().toISOString().replace(/[:.]/g, "-");
  return path.join(OUTPUT_DIR, `domain-context-${runId}.jsonl`);
}

function createJsonlWriter(filePath: string) {
  let queue = Promise.resolve();

  return {
    write(entry: unknown) {
      queue = queue.then(() =>
        appendFile(filePath, `${JSON.stringify(entry)}\n`, "utf8"),
      );
      return queue;
    },
    flush() {
      return queue;
    },
  };
}

async function runWithConcurrency<T>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<void>,
) {
  let nextIndex = 0;

  const workers = Array.from(
    { length: Math.min(limit, items.length) },
    async () => {
      while (true) {
        const currentIndex = nextIndex;
        nextIndex += 1;
        if (currentIndex >= items.length) {
          return;
        }

        await worker(items[currentIndex], currentIndex);
      }
    },
  );

  await Promise.all(workers);
}

if (isDirectRun(import.meta.url)) {
  await scrapePrivatePslDomainContext();
}

function isDirectRun(moduleUrl: string) {
  const entryPath = process.argv[1];
  if (!entryPath) {
    return false;
  }

  return moduleUrl === pathToFileURL(path.resolve(entryPath)).href;
}
