import { readFile } from "node:fs/promises";

const PSL_FILE_URL = new URL("./psl/public_suffix_list.dat", import.meta.url);
const BEGIN_PRIVATE_DOMAINS_MARKER = "// ===BEGIN PRIVATE DOMAINS===";
const END_PRIVATE_DOMAINS_MARKER = "// ===END PRIVATE DOMAINS===";
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

const pslSource = await readFile(PSL_FILE_URL, "utf8");
const pslLines = pslSource.split(/\r?\n/);

const beginMarkerIndex = pslLines.indexOf(BEGIN_PRIVATE_DOMAINS_MARKER);
const endMarkerIndex = pslLines.indexOf(END_PRIVATE_DOMAINS_MARKER);

if (beginMarkerIndex === -1) {
  throw new Error(`Missing marker: ${BEGIN_PRIVATE_DOMAINS_MARKER}`);
}

if (endMarkerIndex === -1) {
  throw new Error(`Missing marker: ${END_PRIVATE_DOMAINS_MARKER}`);
}

if (beginMarkerIndex >= endMarkerIndex) {
  throw new Error("Private domains markers are out of order.");
}

const privatePsl = pslLines.slice(beginMarkerIndex + 1, endMarkerIndex).join("\n");
const privatePslDomains = collectDomains(privatePsl);

export default privatePsl;
export { privatePsl, privatePslDomains };

function collectDomains(text: string) {
  const domains = new Set<string>();

  DOMAIN_EXTRACTOR.lastIndex = 0;
  for (const match of text.matchAll(DOMAIN_EXTRACTOR)) {
    const extracted = match[1] ?? match[2] ?? match[3] ?? match[4] ?? match[5] ?? "";
    addDomain(domains, extracted);
  }

  return removeBareWhenWwwExists(domains);
}

function addDomain(domains: Set<string>, rawDomain: string) {
  const domain = rawDomain.trim().toLowerCase();
  if (!isLikelyDomain(domain)) {
    return;
  }
  domains.add(domain);
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

function removeBareWhenWwwExists(domains: Set<string>) {
  const filtered = new Set(domains);

  for (const domain of domains) {
    if (domain.startsWith("www.")) {
      continue;
    }

    if (domains.has(`www.${domain}`)) {
      filtered.delete(domain);
    }
  }

  return filtered;
}
