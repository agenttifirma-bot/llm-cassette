import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

// Kaatuu, jos repossa oleva nauha (cassette-JSON) sisältää maskaamattoman salaisuuden.
// Skannaa kaikki JSON-tiedostot, jotka ovat cassette-muotoa ({ version: 1, entries: [...] }).

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SKIP_DIRS = new Set(["node_modules", "dist", ".git", "coverage"]);

const SECRET_PARAM = /[?&;](?:key|api_key|apikey|access_token|token)=([^&#"\s]*)/gi;
const SECRET_HEADER = /"(?:authorization|proxy-authorization|x-api-key|x-goog-api-key)"\s*:/i;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+\/-]{8,}/;
const KNOWN_KEY_SHAPES = /\b(?:sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|ghp_[A-Za-z0-9]{30,}|xox[abp]-[A-Za-z0-9-]{10,})/;

/** Palauttaa löydösten kuvaukset (ei koskaan itse arvoa). */
export function findUnmaskedSecrets(raw: string): string[] {
  const findings: string[] = [];
  for (const m of raw.matchAll(SECRET_PARAM)) {
    if (m[1] !== "REDACTED") findings.push("URL-parametri ilman REDACTED-arvoa");
  }
  if (SECRET_HEADER.test(raw)) findings.push("salaisuusotsake tallennettu");
  if (BEARER.test(raw)) findings.push("Bearer-tunniste");
  if (KNOWN_KEY_SHAPES.test(raw)) findings.push("tunnetun avaimen muotoinen merkkijono");
  return findings;
}

function isCassette(raw: string): boolean {
  try {
    const p = JSON.parse(raw) as { version?: unknown; entries?: unknown };
    return p?.version === 1 && Array.isArray(p.entries);
  } catch {
    return false;
  }
}

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (name.endsWith(".json")) out.push(p);
  }
  return out;
}

describe("repon nauhat eivät sisällä salaisuuksia", () => {
  it("jokainen cassette-muotoinen JSON-tiedosto on maskattu", () => {
    const bad: string[] = [];
    for (const file of walk(ROOT)) {
      const raw = readFileSync(file, "utf8");
      if (!isCassette(raw)) continue;
      for (const f of findUnmaskedSecrets(raw)) bad.push(`${relative(ROOT, file)}: ${f}`);
    }
    expect(bad).toEqual([]);
  });

  it("skanneri tunnistaa maskaamattoman URL-avaimen", () => {
    expect(findUnmaskedSecrets('{"url":"http://x/y?key=abc123&alt=json"}')).not.toEqual([]);
    expect(findUnmaskedSecrets('{"url":"http://x/y?a=1&API_KEY=abc"}')).not.toEqual([]);
  });

  it("skanneri tunnistaa otsakkeen, Bearer-tunnisteen ja avainmuodon", () => {
    expect(findUnmaskedSecrets('{"headers":{"Authorization":"x"}}')).not.toEqual([]);
    expect(findUnmaskedSecrets('"Bearer abcdefgh12345678"')).not.toEqual([]);
    expect(findUnmaskedSecrets('"sk-' + "a".repeat(20) + '"')).not.toEqual([]);
  });

  it("skanneri hyväksyy maskatun nauhan", () => {
    expect(findUnmaskedSecrets('{"url":"http://x/y?key=REDACTED&alt=json"}')).toEqual([]);
  });

  it("skanneri ei tulosta löydetyn arvon", () => {
    const f = findUnmaskedSecrets('{"url":"http://x/y?key=TOPSECRETVALUE"}').join(" ");
    expect(f).not.toContain("TOPSECRETVALUE");
  });
});
