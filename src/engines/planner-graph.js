/**
 * @module engines/planner-graph
 * Stage 2 Planner for DEADBOLT:
 * - 2-hop AST symbol & relative ESM/CJS import blast-radius graph
 * - Sub-25us in-process Cascade tier routing via @krusch/toolkit/cascade
 * - Parallel Work Order disjoint AST lease & execution wave solver
 * - SSRF-guarded external GitHub & local repository brownfield scanner
 */

import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { maskCodePreservingNewlines } from 'krusch-stack';
import { okEnvelope, errorEnvelope } from '@krusch/toolkit/http';
import { selectCascadeTier, createTierCircuitBreaker } from '@krusch/toolkit/cascade';
import { scoreLegoBrickCoverage, auditBoilerplateText } from '@krusch/toolkit/catalog';
import { validateOutboundUrl, isPrivateOrReservedIp } from '@krusch/toolkit/security';
import { scrubPrivateNetworkStrings } from '../connectors/hydradb-graph.js';

const execFileAsync = promisify(execFile);

const SCANNABLE_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.jsx',
  '.tsx',
  '.py',
  '.php',
  '.java',
  '.cs',
  '.go',
  '.rb',
  '.rs',
  '.kt'
]);

const POLYGLOT_EXTENSIONS = new Set([
  '.java',
  '.cs',
  '.go',
  '.rb',
  '.rs',
  '.kt'
]);

const SKIPPED_SCAN_DIRS = new Set([
  '.git',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'target',
  'bin',
  'obj',
  'coverage',
  '.next',
  '.cache',
  '.gradle',
  '.mvn',
  '.venv',
  'venv',
  '__pycache__',
  '.krusch-stack'
]);

const SENSITIVE_LOCAL_PREFIXES = [
  '/etc',
  '/private/etc',
  '/root',
  '/proc',
  '/sys',
  '/dev',
  '/boot',
  '/var/run',
  '/private/var/run',
  '/run'
];

const SENSITIVE_SEGMENT_NAMES = new Set([
  '.ssh',
  '.gnupg',
  '.aws',
  '.kube',
  '.docker'
]);

const KNOWN_CHOKE_POINT_BASENAMES = new Set([
  'src/server.js',
  'server.js',
  'src/app.js',
  'app.js',
  'src/index.js',
  'index.js',
  'src/main.js',
  'main.js'
]);

const GITHUB_OWNER_REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/;
const GITHUB_SEGMENT_RE = /^[A-Za-z0-9_.-]+$/;
const RESERVED_GITHUB_ROOTS = new Set([
  'about',
  'codespaces',
  'collections',
  'customer-stories',
  'enterprise',
  'events',
  'explore',
  'features',
  'issues',
  'login',
  'marketplace',
  'new',
  'notifications',
  'organizations',
  'orgs',
  'pricing',
  'pulls',
  'search',
  'security',
  'session',
  'settings',
  'signup',
  'sponsors',
  'team',
  'topics',
  'trending'
]);

/**
 * Normalize common browser-copied GitHub URLs (`/tree/<ref>/...`, `/blob/<ref>/<file>`,
 * `github.com/owner/repo`, `owner/repo`, `git@github.com:owner/repo.git`) while preserving
 * outbound SSRF validation for any non-GitHub or non-HTTPS URL.
 *
 * @param {string} rawInput
 * @returns {{
 *   isRemoteCandidate: boolean,
 *   candidateUrl: string,
 *   repoSlug: string | null,
 *   cleanHttpsUrl: string | null,
 *   displayTarget: string,
 *   hintedFile: string,
 *   invalidGitHubPath: boolean
 * }}
 */
export function normalizeGitHubRepoInput(rawInput) {
  const raw = String(rawInput || '').trim();
  if (!raw) {
    return {
      isRemoteCandidate: false,
      candidateUrl: '',
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: '',
      hintedFile: '',
      invalidGitHubPath: false
    };
  }

  let candidateUrl = raw;
  let isRemoteCandidate = false;
  const strippedRaw = raw.length > 1 ? raw.replace(/\/+$/, '') : raw;
  const httpGitHubMatch = /^http:\/\/((?:www\.)?github\.com)(?=[/?#]|$)(.*)$/i.exec(strippedRaw);

  // 1. SCP-style SSH URL: git@host:owner/repo.git
  const scpMatch = /^git@([A-Za-z0-9.-]+):(.+)$/i.exec(strippedRaw);
  if (scpMatch) {
    isRemoteCandidate = true;
    const sshHost = scpMatch[1].toLowerCase();
    const sshPath = scpMatch[2].replace(/^\/+|\/+$/g, '');
    candidateUrl = `https://${sshHost}/${sshPath}`;
  } else if (/^ssh:\/\/(?:[^@\/]+@)?([A-Za-z0-9.-]+)\/(.+)$/i.test(strippedRaw)) {
    const sshUrlMatch = /^ssh:\/\/(?:[^@\/]+@)?([A-Za-z0-9.-]+)\/(.+)$/i.exec(strippedRaw);
    isRemoteCandidate = true;
    candidateUrl = `https://${sshUrlMatch[1].toLowerCase()}/${sshUrlMatch[2].replace(/\/+$/g, '')}`;
  } else if (httpGitHubMatch) {
    isRemoteCandidate = true;
    candidateUrl = `https://${httpGitHubMatch[1].toLowerCase()}${httpGitHubMatch[2]}`;
  } else if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) {
    isRemoteCandidate = true;
    candidateUrl = strippedRaw;
  } else if (
    /^(?:www\.)?github\.com(?:\/.*)?$/i.test(strippedRaw) &&
    !fs.existsSync(path.resolve(raw)) &&
    !fs.existsSync(path.resolve(strippedRaw))
  ) {
    isRemoteCandidate = true;
    candidateUrl = `https://${strippedRaw}`;
  } else if (
    !strippedRaw.startsWith('.') &&
    !strippedRaw.startsWith('/') &&
    !strippedRaw.includes('\\') &&
    GITHUB_OWNER_REPO_RE.test(strippedRaw) &&
    !fs.existsSync(path.resolve(raw)) &&
    !fs.existsSync(path.resolve(strippedRaw))
  ) {
    const [segA, segB] = strippedRaw.split('/');
    const cleanSegB = segB.replace(/\.git$/i, '');
    if (
      segA !== '.' &&
      segA !== '..' &&
      segA !== '.git' &&
      cleanSegB !== '' &&
      cleanSegB !== '.' &&
      cleanSegB !== '..' &&
      segB !== '.git'
    ) {
      isRemoteCandidate = true;
      candidateUrl = `https://github.com/${segA}/${cleanSegB}`;
    }
  }

  if (!isRemoteCandidate) {
    return {
      isRemoteCandidate: false,
      candidateUrl: raw,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: false
    };
  }

  let parsed = null;
  try {
    parsed = new URL(candidateUrl);
  } catch {
    return {
      isRemoteCandidate: true,
      candidateUrl,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: true
    };
  }

  const hostLower = parsed.hostname.toLowerCase();
  if (
    parsed.protocol !== 'https:' ||
    (hostLower !== 'github.com' && hostLower !== 'www.github.com')
  ) {
    return {
      isRemoteCandidate: true,
      candidateUrl,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: false
    };
  }

  const rawPathPortion = raw.split(/[?#]/)[0];
  const hasDotTraversal = /(?:^|[/:\\])\.\.(?:[\/\\]|$)|%2e%2e/i.test(rawPathPortion);

  const cleanPathname = parsed.pathname.replace(/\/+$/, '');
  let hasMalformedEncoding = false;
  const rawSegments = cleanPathname
    .replace(/^\/+/, '')
    .split('/')
    .filter(Boolean)
    .map((seg) => {
      try {
        return decodeURIComponent(seg);
      } catch {
        hasMalformedEncoding = true;
        return seg;
      }
    });

  const hasDecodedTraversal = rawSegments.some((seg) => {
    const decodedSubSegments = seg.split(/[\/\\]/).filter(Boolean);
    return (
      decodedSubSegments.length === 0 ||
      decodedSubSegments.some((sub) => sub === '.' || sub === '..' || sub.includes('\0'))
    );
  });

  if (
    hasDotTraversal ||
    hasMalformedEncoding ||
    hasDecodedTraversal ||
    rawSegments.length < 2 ||
    rawSegments.some(
      (seg) => seg === '.' || seg === '..' || seg.includes('\\') || seg.includes('\0')
    )
  ) {
    return {
      isRemoteCandidate: true,
      candidateUrl: `https://${hostLower}${cleanPathname}`,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: true
    };
  }

  const owner = rawSegments[0];
  const repo = rawSegments[1].replace(/\.git$/i, '');
  if (
    !owner ||
    !repo ||
    !GITHUB_SEGMENT_RE.test(owner) ||
    !GITHUB_SEGMENT_RE.test(repo) ||
    owner === '.git' ||
    repo === '.git' ||
    repo === '.' ||
    repo === '..' ||
    RESERVED_GITHUB_ROOTS.has(owner.toLowerCase())
  ) {
    return {
      isRemoteCandidate: true,
      candidateUrl: `https://${hostLower}${cleanPathname}`,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: true
    };
  }

  let hintedFile = '';
  if (rawSegments[2] === 'blob' && rawSegments.length >= 5) {
    hintedFile = rawSegments
      .slice(4)
      .join('/')
      .replace(/\/+/g, '/')
      .replace(/^\/+|\/+$/g, '');
  }

  const repoSlug = `${owner}/${repo}`;
  return {
    isRemoteCandidate: true,
    candidateUrl: `https://github.com/${repoSlug}`,
    repoSlug,
    cleanHttpsUrl: `https://github.com/${repoSlug}.git`,
    displayTarget: `https://github.com/${repoSlug}`,
    hintedFile,
    invalidGitHubPath: false
  };
}

/**
 * Normalize a repository-relative POSIX path without leading `./` or `/`.
 * @param {string} rawPath
 * @returns {string}
 */
function normalizeRelPath(rawPath) {
  return String(rawPath || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^(?:\.\/)+/, '')
    .replace(/^\/+/, '');
}

/**
 * Redact private LAN or Tailscale IP literals from display endpoint URLs (`INV-DB-08`).
 * @param {string} rawUrl
 * @returns {string|null}
 */
function redactEndpointUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  try {
    const parsed = new URL(rawUrl.trim());
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    const portSuffix = parsed.port ? `:${parsed.port}` : '';
    if (host === 'localhost') {
      return `${parsed.protocol}//localhost${portSuffix}`;
    }
    if (net.isIP(host) !== 0) {
      const blockedPublic = isPrivateOrReservedIp(host, {
        allowPrivateLan: false,
        allowTailscale: false
      });
      const stillBlockedWhenLanAllowed = isPrivateOrReservedIp(host, {
        allowPrivateLan: true,
        allowTailscale: true
      });
      if (blockedPublic && !stillBlockedWhenLanAllowed) {
        return `${parsed.protocol}//[redacted-private-host]${portSuffix}`;
      }
      if (blockedPublic && stillBlockedWhenLanAllowed) {
        return `${parsed.protocol}//localhost${portSuffix}`;
      }
    }
    return `${parsed.protocol}//${host}${portSuffix}`;
  } catch {
    return '[redacted-endpoint]';
  }
}

/**
 * Redact RFC1918 LAN, CGNAT/Tailscale IPv4, and Tailscale/ULA IPv6 literals from error messages (`INV-DB-08`).
 * @param {string} text
 * @returns {string}
 */
export function scrubPrivateIpLiterals(text) {
  return String(text ?? '')
    .replace(/\[?fd7a:115c:a1e0:[0-9a-f:]*\]?/gi, '[redacted-private-host]')
    .replace(/\[?f[cd][0-9a-f]{2}:(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}\]?/gi, '[redacted-private-host]')
    .replace(
      /(?<![\d.])(?:::ffff:)?(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+)(?!\d)/gi,
      '[redacted-private-host]'
    );
}

/**
 * Query all indexed AST symbols for `repoName` in a single pass and group by normalized file path (`O(N)`),
 * eliminating per-file `stack.git.fileSymbols` synchronous re-indexing storms on polyglot/empty files.
 * @param {object} stack
 * @param {string} repoName
 * @returns {Map<string, Array<object>>}
 */
function loadAllRepoSymbolsByFile(stack, repoName) {
  const byFile = new Map();
  let rows = null;

  if (stack?.db?.prepare) {
    try {
      rows = stack.db
        .prepare(
          'SELECT file_path, symbol_name, symbol_type, start_line, end_line, signature FROM git_symbols WHERE repo_name = ? ORDER BY start_line ASC'
        )
        .all(repoName);
    } catch {
      try {
        rows = stack.db
          .prepare(
            'SELECT file_path, symbol_name, symbol_kind, start_line, end_line, signature, exported FROM git_symbols WHERE repo_name = ? ORDER BY start_line ASC'
          )
          .all(repoName);
      } catch {
        rows = null;
      }
    }
  }

  if (!Array.isArray(rows)) {
    try {
      const searchRes = stack?.git?.searchSymbols?.({ repo: repoName, query: '*', limit: 1000 });
      rows = Array.isArray(searchRes?.data?.symbols) ? searchRes.data.symbols : [];
    } catch {
      rows = [];
    }
  }

  for (const row of rows) {
    if (!row) continue;
    const normFile = normalizeRelPath(row.file_path);
    if (!normFile) continue;
    const symType = row.symbol_type ?? row.symbol_kind ?? 'symbol';
    const normalizedSym = {
      ...row,
      file_path: normFile,
      symbol_name: row.symbol_name,
      symbol_type: symType,
      symbol_kind: row.symbol_kind ?? symType,
      start_line: row.start_line,
      end_line: row.end_line,
      signature: row.signature ?? ''
    };
    let list = byFile.get(normFile);
    if (!list) {
      list = [];
      byFile.set(normFile, list);
    }
    list.push(normalizedSym);
  }

  return byFile;
}

const MAX_REPO_WALK_CANDIDATES = 600;
const MAX_SCANNABLE_FILE_BYTES = 256 * 1024;

const LOW_PRIORITY_SCAN_PATH_RE =
  /(?:^|\/)(?:test|tests|__tests__|spec|specs|example|examples|benchmark|benchmarks|fixtures|mocks|docs|vendor|third_party)(?:\/|$)/i;
const LOW_PRIORITY_SCAN_FILE_RE = /(?:\.(?:test|spec)\.[^/]+|_test\.[^/]+)$/i;
const CORE_PRIORITY_SCAN_DIR_RE =
  /^(?:src|app|lib|pkg|cmd|internal|server|public|controllers|models|services|routes|api)\//i;
const CORE_ROOT_ENTRYPOINT_RE = /^(?:index|main|app|server|config)\.[^/]+$/i;

/**
 * Assign deterministic file scan priority (0 = hintedFile, 1 = core source, 2 = standard, 3 = test/docs/examples).
 * @param {string} relPath
 * @param {string} [normalizedHinted='']
 * @returns {number}
 */
function classifyScanFilePriority(relPath, normalizedHinted = '') {
  if (normalizedHinted && relPath === normalizedHinted) {
    return 0;
  }
  if (LOW_PRIORITY_SCAN_PATH_RE.test(relPath) || LOW_PRIORITY_SCAN_FILE_RE.test(relPath)) {
    return 3;
  }
  if (
    CORE_PRIORITY_SCAN_DIR_RE.test(relPath) ||
    (!relPath.includes('/') && CORE_ROOT_ENTRYPOINT_RE.test(relPath))
  ) {
    return 1;
  }
  return 2;
}

/**
 * Deterministic alphabetical path comparator.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function compareCodePathsAlpha(a, b) {
  const cmp = a.localeCompare(b);
  if (cmp !== 0) return cmp;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Verify that `relPath` resolves safely inside `resolvedRoot` without traversing any symlinks.
 * @param {string} resolvedRoot
 * @param {string} relPath
 * @returns {string|null}
 */
function resolveSafeNonSymlinkFile(resolvedRoot, relPath) {
  const cleanRel = normalizeRelPath(relPath);
  if (!cleanRel || cleanRel.includes('\0')) return null;
  const segments = cleanRel.split('/').filter(Boolean);
  if (segments.length === 0 || segments.some((seg) => seg === '.' || seg === '..')) {
    return null;
  }
  let cur = resolvedRoot;
  for (let i = 0; i < segments.length; i += 1) {
    cur = path.join(cur, segments[i]);
    try {
      const st = fs.lstatSync(cur);
      if (st.isSymbolicLink()) return null;
      if (i < segments.length - 1 && !st.isDirectory()) return null;
      if (i === segments.length - 1 && !st.isFile()) return null;
    } catch {
      return null;
    }
  }
  return cur;
}

/**
 * Validate whether a repository-relative `hintedFile` candidate obeys dotfile, skipped-dir,
 * sensitive-segment, and scannable-extension rules.
 * @param {string} relCandidate
 * @returns {boolean}
 */
function isAllowedHintedRelPath(relCandidate) {
  const clean = normalizeRelPath(relCandidate);
  if (!clean || clean.includes('\0')) return false;
  const ext = path.extname(clean).toLowerCase();
  if (!SCANNABLE_EXTENSIONS.has(ext)) return false;
  const segments = clean.split('/').filter(Boolean);
  if (segments.length === 0) return false;
  for (const seg of segments) {
    const lower = seg.toLowerCase();
    if (
      seg === '.' ||
      seg === '..' ||
      seg.startsWith('.') ||
      SKIPPED_SCAN_DIRS.has(seg) ||
      SKIPPED_SCAN_DIRS.has(lower) ||
      SENSITIVE_SEGMENT_NAMES.has(seg) ||
      SENSITIVE_SEGMENT_NAMES.has(lower)
    ) {
      return false;
    }
  }
  return true;
}

/**
 * Collect candidate non-binary files (`<= 256 KB`) up to `walkCap`, sort by priority tier
 * (`0: hintedFile`, `1: core dirs/entrypoints`, `2: normal`, `3: tests/docs/examples/vendor`),
 * and slice to `maxFiles`.
 * @param {string} rootDir
 * @param {number} maxFiles
 * @param {{ hintedFile?: string, walkCap?: number }} [options={}]
 * @returns {{ files: string[], truncatedOrFiltered: boolean, resolvedHinted: string, hintBlocked: boolean }}
 */
function collectPrioritizedRepoFiles(rootDir, maxFiles = 200, options = {}) {
  const effectiveMaxFiles = Math.max(1, Math.trunc(Number(maxFiles) || 200));
  const safeWalkCap = Math.max(
    effectiveMaxFiles,
    Math.trunc(Number(options?.walkCap) || MAX_REPO_WALK_CANDIDATES)
  );
  const normalizedHinted = normalizeRelPath(options?.hintedFile || '');
  const candidates = [];
  const candidateSet = new Set();
  const resolvedRoot = path.resolve(rootDir);
  const probeBuf = Buffer.allocUnsafe(4096);
  let truncatedOrFiltered = false;

  const checkEligibleCodeFile = (fullPath, recordFiltered = true) => {
    let st = null;
    try {
      st = fs.lstatSync(fullPath);
    } catch {
      if (recordFiltered) truncatedOrFiltered = true;
      return false;
    }
    if (st.isSymbolicLink() || !st.isFile()) {
      if (recordFiltered) truncatedOrFiltered = true;
      return false;
    }
    if (st.size > MAX_SCANNABLE_FILE_BYTES) {
      if (recordFiltered) truncatedOrFiltered = true;
      return false;
    }
    if (st.size === 0) {
      return true;
    }
    let fd = null;
    try {
      fd = fs.openSync(fullPath, 'r');
      const toRead = Math.min(4096, st.size);
      const bytesRead = fs.readSync(fd, probeBuf, 0, toRead, 0);
      if (probeBuf.subarray(0, bytesRead).includes(0)) {
        if (recordFiltered) truncatedOrFiltered = true;
        return false;
      }
      return true;
    } catch {
      if (recordFiltered) truncatedOrFiltered = true;
      return false;
    } finally {
      if (fd !== null) {
        try {
          fs.closeSync(fd);
        } catch {
          // Ignore close error on probe descriptor
        }
      }
    }
  };

  function walk(currentDir) {
    if (candidates.length >= safeWalkCap) {
      truncatedOrFiltered = true;
      return;
    }
    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => compareCodePathsAlpha(a.name, b.name));

    for (const entry of entries) {
      if (candidates.length >= safeWalkCap) {
        truncatedOrFiltered = true;
        break;
      }
      if (entry.name.startsWith('.') || SKIPPED_SCAN_DIRS.has(entry.name)) {
        truncatedOrFiltered = true;
        continue;
      }
      if (entry.isSymbolicLink()) {
        truncatedOrFiltered = true;
        continue;
      }

      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (!SCANNABLE_EXTENSIONS.has(ext)) {
          truncatedOrFiltered = true;
        } else if (checkEligibleCodeFile(fullPath, true)) {
          const rel = path.relative(resolvedRoot, fullPath).replace(/\\/g, '/');
          if (!candidateSet.has(rel)) {
            candidateSet.add(rel);
            candidates.push(rel);
          }
        }
      } else {
        truncatedOrFiltered = true;
      }
    }
  }

  walk(resolvedRoot);

  let resolvedHinted = '';
  let hintBlocked = false;
  if (normalizedHinted) {
    const rawHintSegments = normalizedHinted.split('/').filter(Boolean);
    const hasForbiddenHintSegment =
      normalizedHinted.includes('\0') ||
      rawHintSegments.some((seg) => {
        const lower = seg.toLowerCase();
        return (
          seg === '.' ||
          seg === '..' ||
          seg.startsWith('.') ||
          SKIPPED_SCAN_DIRS.has(seg) ||
          SKIPPED_SCAN_DIRS.has(lower) ||
          SENSITIVE_SEGMENT_NAMES.has(seg) ||
          SENSITIVE_SEGMENT_NAMES.has(lower)
        );
      });

    if (hasForbiddenHintSegment) {
      hintBlocked = true;
    } else {
      let exactExistsOnDisk = false;
      try {
        fs.lstatSync(path.join(resolvedRoot, normalizedHinted));
        exactExistsOnDisk = true;
      } catch {
        exactExistsOnDisk = false;
      }

      if (exactExistsOnDisk) {
        if (isAllowedHintedRelPath(normalizedHinted)) {
          const safeHintedAbs = resolveSafeNonSymlinkFile(resolvedRoot, normalizedHinted);
          if (
            safeHintedAbs &&
            !isSensitiveLocalPath(safeHintedAbs) &&
            checkEligibleCodeFile(safeHintedAbs, false)
          ) {
            resolvedHinted = normalizedHinted;
          } else {
            hintBlocked = true;
          }
        } else {
          hintBlocked = true;
        }
      } else if (rawHintSegments.length >= 2) {
        const matchedSuffixes = [];
        for (let idx = 1; idx < rawHintSegments.length; idx += 1) {
          const suffixRel = rawHintSegments.slice(idx).join('/');
          if (!isAllowedHintedRelPath(suffixRel)) continue;
          const safeSuffixAbs = resolveSafeNonSymlinkFile(resolvedRoot, suffixRel);
          if (
            safeSuffixAbs &&
            !isSensitiveLocalPath(safeSuffixAbs) &&
            checkEligibleCodeFile(safeSuffixAbs, false)
          ) {
            matchedSuffixes.push(suffixRel);
          }
        }
        if (matchedSuffixes.length === 1) {
          resolvedHinted = matchedSuffixes[0];
        }
      }
    }

    if (resolvedHinted && !candidateSet.has(resolvedHinted)) {
      candidateSet.add(resolvedHinted);
      candidates.push(resolvedHinted);
    }
  }

  const priorityHint = resolvedHinted || (!hintBlocked ? normalizedHinted : '');
  candidates.sort((a, b) => {
    const pa = classifyScanFilePriority(a, priorityHint);
    const pb = classifyScanFilePriority(b, priorityHint);
    if (pa !== pb) return pa - pb;
    return compareCodePathsAlpha(a, b);
  });

  if (candidates.length > effectiveMaxFiles) {
    truncatedOrFiltered = true;
    return {
      files: candidates.slice(0, effectiveMaxFiles),
      truncatedOrFiltered,
      resolvedHinted,
      hintBlocked
    };
  }

  return {
    files: candidates,
    truncatedOrFiltered,
    resolvedHinted,
    hintBlocked
  };
}

/**
 * Walk a repository directory and collect bounded code files sorted by scan priority and name.
 * @param {string} rootDir
 * @param {number} maxFiles
 * @param {{ hintedFile?: string, walkCap?: number }} [options={}]
 * @returns {string[]}
 */
function collectRepoCodeFiles(rootDir, maxFiles = 200, options = {}) {
  return collectPrioritizedRepoFiles(rootDir, maxFiles, options).files;
}

/**
 * Extract relative ESM and CommonJS import specifiers from JS/TS source with comments masked.
 * @param {string} source
 * @returns {string[]}
 */
function extractRelativeSpecifiers(source) {
  const noComments = maskCodePreservingNewlines(String(source || ''), { maskStrings: false });
  const specifiers = new Set();

  const patterns = [
    /\b(?:import|export)\s+(?:[^'";\r\n]{1,400}?\s+from\s+)?['"](\.\.?\/[^'"]+)['"]/g,
    /\bimport\s*\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/g
  ];

  for (const regex of patterns) {
    for (const match of noComments.matchAll(regex)) {
      if (match[1]) {
        specifiers.add(match[1].trim());
      }
    }
  }

  return [...specifiers];
}

/**
 * Resolve a relative specifier from `importerRelFile` against known repository file paths.
 * @param {string} importerRelFile
 * @param {string} specifier
 * @param {Set<string>} repoFileSet
 * @returns {string|null}
 */
function resolveRelativeImportTarget(importerRelFile, specifier, repoFileSet) {
  const baseDir = path.posix.dirname(importerRelFile);
  const joined = path.posix.normalize(path.posix.join(baseDir, specifier));
  if (joined.startsWith('..')) return null;

  const candidates = [
    joined,
    `${joined}.js`,
    `${joined}.mjs`,
    `${joined}.cjs`,
    `${joined}.ts`,
    `${joined}.tsx`,
    `${joined}.jsx`,
    `${joined}/index.js`,
    `${joined}/index.ts`,
    `${joined}/index.tsx`
  ];

  for (const candidate of candidates) {
    if (repoFileSet.has(candidate)) {
      return candidate;
    }
  }
  return null;
}

const JS_TS_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx']);

const GO_STDLIB_PACKAGES = new Set([
  'archive/tar',
  'archive/zip',
  'bufio',
  'bytes',
  'cmp',
  'compress/gzip',
  'container/heap',
  'container/list',
  'context',
  'crypto',
  'crypto/aes',
  'crypto/cipher',
  'crypto/ecdsa',
  'crypto/ed25519',
  'crypto/hmac',
  'crypto/md5',
  'crypto/rand',
  'crypto/rsa',
  'crypto/sha1',
  'crypto/sha256',
  'crypto/sha512',
  'crypto/subtle',
  'crypto/tls',
  'crypto/x509',
  'database/sql',
  'embed',
  'encoding/base64',
  'encoding/binary',
  'encoding/csv',
  'encoding/hex',
  'encoding/json',
  'encoding/pem',
  'encoding/xml',
  'errors',
  'expvar',
  'flag',
  'fmt',
  'html',
  'html/template',
  'io',
  'io/fs',
  'io/ioutil',
  'log',
  'log/slog',
  'maps',
  'math',
  'math/big',
  'math/rand',
  'mime',
  'mime/multipart',
  'net',
  'net/http',
  'net/http/httptest',
  'net/mail',
  'net/netip',
  'net/smtp',
  'net/url',
  'os',
  'os/exec',
  'os/signal',
  'os/user',
  'path',
  'path/filepath',
  'reflect',
  'regexp',
  'runtime',
  'runtime/debug',
  'slices',
  'sort',
  'strconv',
  'strings',
  'sync',
  'sync/atomic',
  'syscall',
  'testing',
  'text/scanner',
  'text/tabwriter',
  'text/template',
  'time',
  'unicode',
  'unicode/utf8',
  'unsafe'
]);

/**
 * Strip `//` and `/* ... *\/` comments outside strings in linear time while preserving newlines.
 * @param {string} source
 * @param {boolean} [allowBacktickRawStrings=false]
 * @returns {string}
 */
function stripCStyleComments(source, allowBacktickRawStrings = false) {
  const raw = String(source || '');
  let out = '';
  let i = 0;
  const len = raw.length;

  while (i < len) {
    const ch = raw[i];
    const next = raw[i + 1];

    if (allowBacktickRawStrings && ch === '`') {
      out += ch;
      i += 1;
      while (i < len) {
        out += raw[i];
        if (raw[i] === '`') {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      const quote = ch;
      out += ch;
      i += 1;
      while (i < len) {
        if (raw[i] === '\\' && i + 1 < len) {
          out += raw[i] + raw[i + 1];
          i += 2;
          continue;
        }
        out += raw[i];
        if (raw[i] === quote || raw[i] === '\n') {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }

    if (ch === '/' && next === '*') {
      out += '  ';
      i += 2;
      while (i < len && !(raw[i] === '*' && raw[i + 1] === '/')) {
        out += raw[i] === '\n' ? '\n' : ' ';
        i += 1;
      }
      if (i < len) {
        out += '  ';
        i += 2;
      }
      continue;
    }

    if (ch === '/' && next === '/') {
      while (i < len && raw[i] !== '\n') {
        out += ' ';
        i += 1;
      }
      continue;
    }

    out += ch;
    i += 1;
  }

  return out;
}

/**
 * Strip `#` line comments outside single, double, or triple-quoted strings while preserving newlines.
 * @param {string} source
 * @returns {string}
 */
function stripHashComments(source) {
  const raw = String(source || '');
  let out = '';
  let i = 0;
  const len = raw.length;

  while (i < len) {
    const ch = raw[i];
    if (
      (ch === '"' || ch === "'") &&
      raw[i + 1] === ch &&
      raw[i + 2] === ch
    ) {
      const triple = ch + ch + ch;
      out += triple;
      i += 3;
      while (i < len) {
        if (raw[i] === '\\' && i + 1 < len) {
          out += raw[i] + raw[i + 1];
          i += 2;
          continue;
        }
        if (raw[i] === ch && raw[i + 1] === ch && raw[i + 2] === ch) {
          out += triple;
          i += 3;
          break;
        }
        out += raw[i];
        i += 1;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      const quote = ch;
      out += ch;
      i += 1;
      while (i < len) {
        if (raw[i] === '\\' && i + 1 < len) {
          out += raw[i] + raw[i + 1];
          i += 2;
          continue;
        }
        out += raw[i];
        if (raw[i] === quote || raw[i] === '\n') {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }

    if (ch === '#') {
      while (i < len && raw[i] !== '\n') {
        out += ' ';
        i += 1;
      }
      continue;
    }

    out += ch;
    i += 1;
  }

  return out;
}

/**
 * Resolve a normalized JS/TS module stem (without leading `/` or `..`) against `repoFileSet`.
 * @param {string} importerRelFile
 * @param {string} normalizedBase
 * @param {Set<string>} repoFileSet
 * @returns {string|null}
 */
function resolveJsTsCandidateBase(importerRelFile, normalizedBase, repoFileSet) {
  const clean = normalizeRelPath(normalizedBase);
  if (!clean || clean.startsWith('..')) return null;

  const candidates = [
    clean,
    `${clean}.ts`,
    `${clean}.tsx`,
    `${clean}.js`,
    `${clean}.jsx`,
    `${clean}.mjs`,
    `${clean}.cjs`,
    `${clean}/index.ts`,
    `${clean}/index.tsx`,
    `${clean}/index.js`,
    `${clean}/index.jsx`,
    `${clean}/index.mjs`,
    `${clean}/index.cjs`
  ];

  const jsExtMatch = /\.(?:js|mjs|cjs|jsx)$/i.exec(clean);
  if (jsExtMatch) {
    const stem = clean.slice(0, -jsExtMatch[0].length);
    candidates.push(`${stem}.ts`, `${stem}.tsx`);
  }

  for (const cand of candidates) {
    if (cand !== importerRelFile && repoFileSet.has(cand)) {
      return cand;
    }
  }
  return null;
}

/**
 * Resolve JS/TS relative (`./`, `../`) and path-alias (`@/`, `~/`) specifiers against `repoFileSet`.
 * @param {string} importerRelFile
 * @param {string} rawSpec
 * @param {Set<string>} repoFileSet
 * @returns {string|null}
 */
function resolveJsTsSpecifier(importerRelFile, rawSpec, repoFileSet) {
  const spec = String(rawSpec || '').trim().split(/[?#]/)[0].trim();
  if (!spec) return null;

  if (spec.startsWith('./') || spec.startsWith('../')) {
    const baseDir = path.posix.dirname(importerRelFile);
    const joined = path.posix.normalize(path.posix.join(baseDir, spec));
    if (joined.startsWith('..')) return null;
    return resolveJsTsCandidateBase(importerRelFile, joined, repoFileSet);
  }

  if (spec.startsWith('@/') || spec.startsWith('~/')) {
    const subPath = path.posix.normalize(spec.slice(2).replace(/^\/+/, ''));
    if (!subPath || subPath === '.' || subPath.startsWith('..')) return null;

    const roots = [];
    const srcIdx = importerRelFile.indexOf('/src/');
    if (srcIdx !== -1) {
      roots.push(`${importerRelFile.slice(0, srcIdx + 4)}/${subPath}`);
      roots.push(`${importerRelFile.slice(0, srcIdx)}/${subPath}`);
    }
    roots.push(`src/${subPath}`, subPath, `app/${subPath}`);

    for (const candidateBase of roots) {
      const resolved = resolveJsTsCandidateBase(importerRelFile, candidateBase, repoFileSet);
      if (resolved) return resolved;
    }
  }

  return null;
}

/**
 * Expand Rust `use` trees (including nested `{a, b::c}` brace groups) into flat `::`-delimited paths.
 * @param {string} rawExpr
 * @param {number} [depth=0]
 * @returns {string[]}
 */
function expandRustUseTree(rawExpr, depth = 0) {
  if (depth > 4) return [];
  const expr = String(rawExpr || '')
    .trim()
    .replace(/\s+as\s+[A-Za-z_][A-Za-z0-9_]*$/g, '')
    .trim();
  if (!expr) return [];

  const openIdx = expr.indexOf('{');
  if (openIdx === -1) {
    return [expr];
  }

  let braceDepth = 0;
  let closeIdx = -1;
  for (let i = openIdx; i < expr.length; i += 1) {
    if (expr[i] === '{') braceDepth += 1;
    else if (expr[i] === '}') {
      braceDepth -= 1;
      if (braceDepth === 0) {
        closeIdx = i;
        break;
      }
    }
  }
  if (closeIdx === -1) return [];

  const head = expr.slice(0, openIdx).trim().replace(/::$/, '');
  const inner = expr.slice(openIdx + 1, closeIdx);
  const parts = [];
  let cur = '';
  let innerDepth = 0;
  for (let i = 0; i < inner.length; i += 1) {
    const ch = inner[i];
    if (ch === '{') innerDepth += 1;
    else if (ch === '}') innerDepth -= 1;
    if (ch === ',' && innerDepth === 0) {
      if (cur.trim()) parts.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) parts.push(cur.trim());

  const expanded = [];
  for (const part of parts) {
    if (expanded.length >= 24) break;
    if (part === 'self') {
      if (head) expanded.push(head);
      continue;
    }
    const subPaths = expandRustUseTree(part, depth + 1);
    for (const sub of subPaths) {
      if (expanded.length >= 24) break;
      expanded.push(head ? `${head}::${sub}` : sub);
    }
  }
  return expanded;
}

/**
 * Extract deterministic static import/dependency edges across polyglot source files
 * (TS/JS path aliases & relative imports, Python, Go, Rust, Java, Kotlin, C#, Ruby, and PHP).
 * Emits `{ from, to, type: 'IMPORTS' }` where `from !== to` and `to` exists in `scannedFiles`,
 * deduplicated by `${from}->${to}`.
 *
 * @param {Array<{ filePath?: string, file_path?: string, path?: string, content?: string, code?: string }>|Record<string, string>} scannedFiles
 * @returns {Array<{ from: string, to: string, type: 'IMPORTS' }>}
 */
export function extractPolyglotDependencyEdges(scannedFiles = []) {
  const entries = [];
  if (Array.isArray(scannedFiles)) {
    for (const item of scannedFiles) {
      if (!item || typeof item !== 'object') continue;
      const fp = normalizeRelPath(item.filePath ?? item.file_path ?? item.path ?? '');
      if (!fp) continue;
      entries.push({
        filePath: fp,
        content: String(item.content ?? item.code ?? '')
      });
    }
  } else if (scannedFiles && typeof scannedFiles === 'object') {
    for (const [rawPath, rawContent] of Object.entries(scannedFiles)) {
      const fp = normalizeRelPath(rawPath);
      if (!fp) continue;
      entries.push({
        filePath: fp,
        content: String(rawContent ?? '')
      });
    }
  }

  if (entries.length < 2) return [];

  const repoFileSet = new Set(entries.map((e) => e.filePath));
  const sortedPaths = [...repoFileSet].sort(compareCodePathsAlpha);
  const goFiles = sortedPaths.filter((p) => p.endsWith('.go'));
  const jvmFiles = sortedPaths.filter((p) => p.endsWith('.java') || p.endsWith('.kt'));
  const csFiles = sortedPaths.filter((p) => p.endsWith('.cs'));

  const edges = [];
  const seenEdge = new Set();
  const addEdge = (from, to) => {
    if (!from || !to || from === to) return false;
    if (!repoFileSet.has(from) || !repoFileSet.has(to)) return false;
    const key = `${from}->${to}`;
    if (seenEdge.has(key)) return false;
    seenEdge.add(key);
    edges.push({ from, to, type: 'IMPORTS' });
    return true;
  };

  // Pre-index JVM (.java, .kt) packages & declared class/object/interface names
  const jvmMetaByFile = new Map();
  const jvmFqcnToFiles = new Map();
  const jvmPkgToMeta = new Map();

  for (const entry of entries) {
    const ext = path.extname(entry.filePath).toLowerCase();
    if (ext !== '.java' && ext !== '.kt') continue;
    const cleaned = stripCStyleComments(entry.content, false);
    const pkgMatch = /^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)/m.exec(cleaned);
    const pkg = pkgMatch ? pkgMatch[1] : '';
    const classSet = new Set();
    const stem = path.posix.basename(entry.filePath, ext);
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(stem)) {
      classSet.add(stem);
    }
    for (const m of cleaned.matchAll(/\b(?:class|interface|enum|record|object)\s+([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
      if (m[1]) classSet.add(m[1]);
    }
    const meta = {
      filePath: entry.filePath,
      ext,
      cleaned,
      pkg,
      classNames: [...classSet]
    };
    jvmMetaByFile.set(entry.filePath, meta);
    if (pkg) {
      if (!jvmPkgToMeta.has(pkg)) jvmPkgToMeta.set(pkg, []);
      jvmPkgToMeta.get(pkg).push(meta);
      for (const cn of meta.classNames) {
        const fqcn = `${pkg}.${cn}`;
        if (!jvmFqcnToFiles.has(fqcn)) jvmFqcnToFiles.set(fqcn, []);
        jvmFqcnToFiles.get(fqcn).push(entry.filePath);
      }
    }
  }

  // Pre-index C# (.cs) namespaces & declared type names
  const csMetaByFile = new Map();
  const csNamespaceToFiles = new Map();
  const csNamespaceToMeta = new Map();

  for (const entry of entries) {
    if (!entry.filePath.toLowerCase().endsWith('.cs')) continue;
    const cleaned = stripCStyleComments(entry.content, false);
    const namespaces = [];
    for (const m of cleaned.matchAll(/\bnamespace\s+([A-Za-z_][A-Za-z0-9_.]*)\s*[;{]/g)) {
      if (m[1] && !namespaces.includes(m[1])) {
        namespaces.push(m[1]);
      }
    }
    const typeSet = new Set();
    const stem = path.posix.basename(entry.filePath, path.extname(entry.filePath));
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(stem)) {
      typeSet.add(stem);
    }
    for (const m of cleaned.matchAll(/\b(?:class|interface|struct|record|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
      if (m[1]) typeSet.add(m[1]);
    }
    const meta = {
      filePath: entry.filePath,
      cleaned,
      namespaces,
      typeNames: [...typeSet]
    };
    csMetaByFile.set(entry.filePath, meta);
    for (const ns of namespaces) {
      if (!csNamespaceToFiles.has(ns)) csNamespaceToFiles.set(ns, []);
      csNamespaceToFiles.get(ns).push(entry.filePath);
      if (!csNamespaceToMeta.has(ns)) csNamespaceToMeta.set(ns, []);
      csNamespaceToMeta.get(ns).push(meta);
    }
  }
  for (const fileList of csNamespaceToFiles.values()) {
    fileList.sort(compareCodePathsAlpha);
  }

  for (const entry of entries) {
    const from = entry.filePath;
    const ext = path.extname(from).toLowerCase();

    // 1. JS / TS relative + `@/` and `~/` path aliases
    if (JS_TS_EXTENSIONS.has(ext)) {
      const masked = maskCodePreservingNewlines(entry.content, { maskStrings: false });
      const specs = new Set();
      const jsPatterns = [
        /\b(?:import|export)\s+(?:[^'";]{1,600}?\s+from\s+)?['"]((?:\.\.?\/|@\/|~\/)[^'"]+)['"]/g,
        /\b(?:import|require)\s*\(\s*['"]((?:\.\.?\/|@\/|~\/)[^'"]+)['"]\s*\)/g
      ];
      for (const regex of jsPatterns) {
        for (const m of masked.matchAll(regex)) {
          if (m[1]) specs.add(m[1].trim());
        }
      }
      for (const spec of specs) {
        const resolved = resolveJsTsSpecifier(from, spec, repoFileSet);
        if (resolved) addEdge(from, resolved);
      }
      continue;
    }

    // 2. Python (.py) absolute dotted & relative `.` / `..` imports
    if (ext === '.py') {
      const cleanedPy = stripHashComments(entry.content).replace(/\\\r?\n/g, ' ');
      const fromDir = path.posix.dirname(from) === '.' ? '' : path.posix.dirname(from);
      const ancestorRoots = ['', 'src/'];
      let walkDir = fromDir;
      while (walkDir && walkDir !== '.') {
        const prefix = `${walkDir}/`;
        if (!ancestorRoots.includes(prefix)) ancestorRoots.push(prefix);
        const parent = path.posix.dirname(walkDir);
        if (parent === walkDir) break;
        walkDir = parent === '.' ? '' : parent;
      }

      const tryPyModuleCandidates = (relModulePath) => {
        const cleanMod = normalizeRelPath(relModulePath);
        if (!cleanMod || cleanMod.startsWith('..')) return false;
        const pyFile = `${cleanMod}.py`;
        const initFile = `${cleanMod}/__init__.py`;
        let matched = false;
        if (pyFile !== from && repoFileSet.has(pyFile)) {
          addEdge(from, pyFile);
          matched = true;
        } else if (initFile !== from && repoFileSet.has(initFile)) {
          addEdge(from, initFile);
          matched = true;
        }
        return matched;
      };

      const handlePyFromImport = (rawModSpec, rawNames) => {
        const specTrim = String(rawModSpec || '').trim();
        if (!specTrim) return;
        const dotMatch = /^(\.*)(.*)$/.exec(specTrim);
        if (!dotMatch) return;
        const dots = dotMatch[1] || '';
        const modRest = (dotMatch[2] || '').trim();
        const names = String(rawNames || '')
          .split(',')
          .map((n) => n.trim().split(/\s+as\s+/)[0].trim())
          .filter((n) => n && n !== '*' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(n));

        if (dots.length > 0) {
          let baseDir = fromDir;
          let validUp = true;
          for (let up = 1; up < dots.length; up += 1) {
            if (!baseDir) {
              validUp = false;
              break;
            }
            const nextParent = path.posix.dirname(baseDir);
            baseDir = nextParent === '.' ? '' : nextParent;
          }
          if (!validUp) return;

          const modRel = modRest ? modRest.replace(/\./g, '/') : '';
          const baseRel = [baseDir, modRel].filter(Boolean).join('/');
          let anyNameResolvedAsModule = false;
          for (const name of names) {
            const subCandidate = [baseRel, name].filter(Boolean).join('/');
            if (tryPyModuleCandidates(subCandidate)) {
              anyNameResolvedAsModule = true;
            }
          }
          if (!anyNameResolvedAsModule && baseRel) {
            tryPyModuleCandidates(baseRel);
          }
          return;
        }

        if (!modRest || !/^[A-Za-z_][A-Za-z0-9_.]*$/.test(modRest)) return;
        const modPath = modRest.replace(/\./g, '/');
        for (const rootPrefix of ancestorRoots) {
          let matchedAtRoot = false;
          for (const name of names) {
            if (tryPyModuleCandidates(`${rootPrefix}${modPath}/${name}`)) {
              matchedAtRoot = true;
            }
          }
          if (tryPyModuleCandidates(`${rootPrefix}${modPath}`)) {
            matchedAtRoot = true;
          }
          if (matchedAtRoot) break;
        }
      };

      for (const m of cleanedPy.matchAll(/^[ \t]*from[ \t]+(\.*[A-Za-z0-9_.]*)[ \t]+import[ \t]+\(([^)]*)\)/gm)) {
        handlePyFromImport(m[1], m[2]);
      }
      for (const m of cleanedPy.matchAll(/^[ \t]*from[ \t]+(\.*[A-Za-z0-9_.]*)[ \t]+import[ \t]+([^\n(]+)/gm)) {
        handlePyFromImport(m[1], m[2]);
      }
      for (const m of cleanedPy.matchAll(/^[ \t]*import[ \t]+([^\n]+)/gm)) {
        const items = String(m[1] || '').split(',');
        for (const rawItem of items) {
          const modName = rawItem.trim().split(/\s+as\s+/)[0].trim();
          if (!modName || !/^[A-Za-z_][A-Za-z0-9_.]*$/.test(modName)) continue;
          const modPath = modName.replace(/\./g, '/');
          for (const rootPrefix of ancestorRoots) {
            if (tryPyModuleCandidates(`${rootPrefix}${modPath}`)) {
              break;
            }
          }
        }
      }
      continue;
    }

    // 3. Go (.go) single and grouped `import ( ... )` blocks
    if (ext === '.go') {
      const cleanedGo = stripCStyleComments(entry.content, true);
      const goImports = new Set();
      for (const blockMatch of cleanedGo.matchAll(/\bimport\s*\(([\s\S]*?)\)/g)) {
        const body = blockMatch[1] || '';
        for (const lineMatch of body.matchAll(/(?:[A-Za-z0-9_.]+\s+)?["`]([^"`\s]+)["`]/g)) {
          if (lineMatch[1]) goImports.add(lineMatch[1].trim());
        }
      }
      for (const singleMatch of cleanedGo.matchAll(/\bimport\s+(?:[A-Za-z0-9_.]+\s+)?["`]([^"`\s]+)["`]/g)) {
        if (singleMatch[1]) goImports.add(singleMatch[1].trim());
      }

      const fromIsTest = from.endsWith('_test.go');
      for (const imp of goImports) {
        if (GO_STDLIB_PACKAGES.has(imp)) continue;
        const segs = imp.replace(/^\/+|\/+$/g, '').split('/').filter(Boolean);
        if (segs.length === 0) continue;

        const pkgName = segs[segs.length - 1];
        const tailTwo = segs.length >= 2 ? `${segs[segs.length - 2]}/${pkgName}` : pkgName;
        const afterRepo = segs.length > 3 ? segs.slice(3).join('/') : '';
        const afterMod = segs.length > 1 ? segs.slice(1).join('/') : '';

        const tierA = [];
        const tierB = [];
        const tierC = [];

        for (const cand of goFiles) {
          if (cand === from) continue;
          if (!fromIsTest && cand.endsWith('_test.go')) continue;
          const candDir = path.posix.dirname(cand) === '.' ? '' : path.posix.dirname(cand);
          if (
            (afterRepo && (candDir === afterRepo || candDir.endsWith(`/${afterRepo}`))) ||
            (afterMod && candDir === afterMod)
          ) {
            tierA.push(cand);
          } else if (candDir === tailTwo || candDir.endsWith(`/${tailTwo}`)) {
            tierB.push(cand);
          } else if (
            candDir === pkgName ||
            (segs.length === 1 && candDir.endsWith(`/${pkgName}`))
          ) {
            tierC.push(cand);
          }
        }

        const chosen = tierA.length > 0 ? tierA : tierB.length > 0 ? tierB : tierC;
        let emittedForImport = 0;
        for (const target of chosen) {
          if (emittedForImport >= 6) break;
          addEdge(from, target);
          emittedForImport += 1;
        }
      }
      continue;
    }

    // 4. Rust (.rs) `mod foo;`, `use crate::...`, `use super::...`, `use self::...`
    if (ext === '.rs') {
      const cleanedRs = stripCStyleComments(entry.content, false);
      const fromBase = path.posix.basename(from);
      const fromDir = path.posix.dirname(from) === '.' ? '' : path.posix.dirname(from);
      const srcMarkerIdx = from.indexOf('/src/');
      const crateRoots =
        srcMarkerIdx !== -1
          ? [from.slice(0, srcMarkerIdx + 4)]
          : from.startsWith('src/')
            ? ['src']
            : ['src', ''];

      const isRootOrModFile =
        fromBase === 'lib.rs' || fromBase === 'main.rs' || fromBase === 'mod.rs';
      const selfModuleDir = isRootOrModFile
        ? fromDir
        : [fromDir, path.posix.basename(from, '.rs')].filter(Boolean).join('/');

      const tryRustModPath = (modRelPath) => {
        const cleanRel = normalizeRelPath(modRelPath);
        if (!cleanRel || cleanRel.startsWith('..')) return false;
        const directRs = `${cleanRel}.rs`;
        const folderModRs = `${cleanRel}/mod.rs`;
        if (directRs !== from && repoFileSet.has(directRs)) {
          addEdge(from, directRs);
          return true;
        }
        if (folderModRs !== from && repoFileSet.has(folderModRs)) {
          addEdge(from, folderModRs);
          return true;
        }
        return false;
      };

      const resolveRustPrefixSegments = (baseDir, segs) => {
        const cleanSegs = segs.filter((s) => s && s !== '*' && s !== 'self');
        for (let len = cleanSegs.length; len >= 1; len -= 1) {
          const prefixRel = [baseDir, ...cleanSegs.slice(0, len)].filter(Boolean).join('/');
          if (tryRustModPath(prefixRel)) {
            return true;
          }
        }
        return false;
      };

      for (const modMatch of cleanedRs.matchAll(/\b(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/g)) {
        const modName = modMatch[1];
        if (!modName) continue;
        const modSearchDirs = isRootOrModFile ? [fromDir] : [selfModuleDir, fromDir];
        for (const base of modSearchDirs) {
          if (tryRustModPath([base, modName].filter(Boolean).join('/'))) {
            break;
          }
        }
      }

      for (const useMatch of cleanedRs.matchAll(/\b(?:pub(?:\s*\([^)]*\))?\s+)?use\s+([^;]+);/g)) {
        const expanded = expandRustUseTree(useMatch[1]);
        for (const usePath of expanded) {
          const rawSegs = usePath.split('::').map((s) => s.trim()).filter(Boolean);
          if (rawSegs.length === 0) continue;

          if (rawSegs[0] === 'crate') {
            const rest = rawSegs.slice(1);
            for (const cRoot of crateRoots) {
              if (resolveRustPrefixSegments(cRoot, rest)) break;
            }
          } else if (rawSegs[0] === 'self') {
            const rest = rawSegs.slice(1);
            if (!resolveRustPrefixSegments(selfModuleDir, rest) && selfModuleDir !== fromDir) {
              resolveRustPrefixSegments(fromDir, rest);
            }
          } else if (rawSegs[0] === 'super') {
            let superCount = 0;
            while (superCount < rawSegs.length && rawSegs[superCount] === 'super') {
              superCount += 1;
            }
            const rest = rawSegs.slice(superCount);
            let curModDir = fromBase === 'mod.rs' ? fromDir : selfModuleDir;
            let validSuper = true;
            for (let s = 0; s < superCount; s += 1) {
              if (!curModDir) {
                validSuper = false;
                break;
              }
              const nextDir = path.posix.dirname(curModDir);
              curModDir = nextDir === '.' ? '' : nextDir;
            }
            if (validSuper) {
              const matchedChild = resolveRustPrefixSegments(curModDir, rest);
              if (!matchedChild && curModDir) {
                tryRustModPath(curModDir);
              }
            }
          }
        }
      }
      continue;
    }

    // 5. Java & Kotlin (.java, .kt) explicit imports + same-package class references
    if (ext === '.java' || ext === '.kt') {
      const meta = jvmMetaByFile.get(from);
      if (!meta) continue;
      const bodyWithoutHeaders = meta.cleaned
        .replace(/^\s*package\s+[^\n]+/gm, ' ')
        .replace(/^\s*import\s+[^\n]+/gm, ' ');
      const bodyIdents = new Set(bodyWithoutHeaders.match(/\b[A-Za-z_][A-Za-z0-9_]*\b/g) || []);

      const matchJvmFqcnOrSuffix = (fqcn) => {
        const indexed = jvmFqcnToFiles.get(fqcn) || [];
        let matched = false;
        for (const target of indexed) {
          if (target !== from) {
            addEdge(from, target);
            matched = true;
          }
        }
        const slashPath = fqcn.replace(/\./g, '/');
        const suffixes = [`${slashPath}.java`, `${slashPath}.kt`];
        for (const cand of jvmFiles) {
          if (cand === from) continue;
          if (suffixes.some((suf) => cand === suf || cand.endsWith(`/${suf}`))) {
            addEdge(from, cand);
            matched = true;
          }
        }
        return matched;
      };

      for (const impMatch of meta.cleaned.matchAll(/^\s*import\s+(?:static\s+)?([A-Za-z_][A-Za-z0-9_.*]*)(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*;?/gm)) {
        const rawImp = (impMatch[1] || '').trim();
        if (!rawImp) continue;
        if (rawImp.endsWith('.*')) {
          const wildcardPkg = rawImp.slice(0, -2);
          const peers = jvmPkgToMeta.get(wildcardPkg) || [];
          let wildcardAdded = 0;
          for (const peer of peers) {
            if (wildcardAdded >= 6) break;
            if (peer.filePath === from) continue;
            if (peer.classNames.some((cn) => bodyIdents.has(cn))) {
              addEdge(from, peer.filePath);
              wildcardAdded += 1;
            }
          }
          continue;
        }

        if (!matchJvmFqcnOrSuffix(rawImp)) {
          const lastDot = rawImp.lastIndexOf('.');
          if (lastDot > 0) {
            matchJvmFqcnOrSuffix(rawImp.slice(0, lastDot));
          }
        }
      }

      if (meta.pkg) {
        const samePkgPeers = jvmPkgToMeta.get(meta.pkg) || [];
        for (const peer of samePkgPeers) {
          if (peer.filePath === from) continue;
          if (peer.classNames.some((cn) => bodyIdents.has(cn))) {
            addEdge(from, peer.filePath);
          }
        }
      }
      continue;
    }

    // 6. C# (.cs) `using Foo.Bar;` + same-namespace peer type references
    if (ext === '.cs') {
      const meta = csMetaByFile.get(from);
      if (!meta) continue;

      for (const usingMatch of meta.cleaned.matchAll(/^\s*(?:global\s+)?using\s+(?:static\s+)?(?!var\b)(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?([A-Za-z_][A-Za-z0-9_.]*)\s*;/gm)) {
        const ns = (usingMatch[1] || '').trim();
        if (!ns) continue;

        const matchedTargets = [];
        const byNs = csNamespaceToFiles.get(ns) || [];
        for (const target of byNs) {
          if (target !== from && !matchedTargets.includes(target)) {
            matchedTargets.push(target);
          }
        }

        if (matchedTargets.length === 0) {
          const lastDot = ns.lastIndexOf('.');
          if (lastDot > 0) {
            const parentNs = ns.slice(0, lastDot);
            const typeName = ns.slice(lastDot + 1);
            const parentPeers = csNamespaceToMeta.get(parentNs) || [];
            for (const peer of parentPeers) {
              if (
                peer.filePath !== from &&
                peer.typeNames.includes(typeName) &&
                !matchedTargets.includes(peer.filePath)
              ) {
                matchedTargets.push(peer.filePath);
              }
            }
          }
        }

        if (matchedTargets.length === 0) {
          const nsSlashLower = ns.replace(/\./g, '/').toLowerCase();
          for (const cand of csFiles) {
            if (cand === from) continue;
            const candDirLower = (
              path.posix.dirname(cand) === '.' ? '' : path.posix.dirname(cand)
            ).toLowerCase();
            if (candDirLower === nsSlashLower || candDirLower.endsWith(`/${nsSlashLower}`)) {
              matchedTargets.push(cand);
            }
          }
        }

        for (const target of matchedTargets.slice(0, 6)) {
          addEdge(from, target);
        }
      }

      if (meta.namespaces.length > 0) {
        const bodyNoUsing = meta.cleaned.replace(/^\s*(?:global\s+)?using\s+[^\n]+/gm, ' ');
        const bodyIdents = new Set(bodyNoUsing.match(/\b[A-Za-z_][A-Za-z0-9_]*\b/g) || []);
        for (const ns of meta.namespaces) {
          let sameNsAdded = 0;
          for (const peer of csNamespaceToMeta.get(ns) || []) {
            if (sameNsAdded >= 6) break;
            if (peer.filePath === from) continue;
            if (peer.typeNames.some((tn) => bodyIdents.has(tn))) {
              addEdge(from, peer.filePath);
              sameNsAdded += 1;
            }
          }
        }
      }
      continue;
    }

    // 7. Ruby (.rb) `require_relative` and `require`
    if (ext === '.rb') {
      const cleanedRb = stripHashComments(entry.content);
      const fromDir = path.posix.dirname(from) === '.' ? '' : path.posix.dirname(from);

      for (const reqRelMatch of cleanedRb.matchAll(/\brequire_relative\s*(?:\(\s*)?['"]([^'"]+)['"]\s*\)?/g)) {
        const rawSpec = (reqRelMatch[1] || '').trim();
        if (!rawSpec) continue;
        const joined = path.posix.normalize(path.posix.join(fromDir || '.', rawSpec));
        if (joined.startsWith('..')) continue;
        for (const cand of [joined, `${joined}.rb`]) {
          if (cand !== from && repoFileSet.has(cand)) {
            addEdge(from, cand);
            break;
          }
        }
      }

      for (const reqMatch of cleanedRb.matchAll(/\brequire\s*(?:\(\s*)?['"]([^'"]+)['"]\s*\)?/g)) {
        const rawSpec = (reqMatch[1] || '').trim();
        if (!rawSpec) continue;

        const candidates = [];
        if (rawSpec.startsWith('./') || rawSpec.startsWith('../')) {
          const relJoined = path.posix.normalize(path.posix.join(fromDir || '.', rawSpec));
          if (!relJoined.startsWith('..')) {
            candidates.push(relJoined, `${relJoined}.rb`);
          }
        }
        const cleanSpec = rawSpec.replace(/^(?:\.\/)+/, '').replace(/^\/+/, '');
        if (cleanSpec && !cleanSpec.startsWith('..')) {
          const prefixes = ['lib/', 'app/', '', ...(fromDir ? [`${fromDir}/`] : [])];
          for (const prefix of prefixes) {
            candidates.push(`${prefix}${cleanSpec}`, `${prefix}${cleanSpec}.rb`);
          }
        }

        for (const cand of candidates) {
          if (cand !== from && repoFileSet.has(cand)) {
            addEdge(from, cand);
            break;
          }
        }
      }
      continue;
    }

    // 8. PHP (.php) `require` / `include` / route links
    if (ext === '.php') {
      for (const dep of extractPhpDependencies(entry.content)) {
        const target = resolvePhpDependencyTarget(from, dep.specifier, repoFileSet);
        if (target) {
          addEdge(from, target);
        }
      }
    }
  }

  return edges;
}

/**
 * Mask PHP block (`/* ... *\/`), line (`//`), and hash (`#`, excluding `#[` attributes)
 * comments outside single/double-quoted strings while preserving newlines.
 * @param {string} source
 * @returns {string}
 */
function stripPhpCommentsPreservingNewlines(source) {
  const raw = String(source || '');
  let out = '';
  let i = 0;
  const len = raw.length;

  while (i < len) {
    const ch = raw[i];
    const next = raw[i + 1];

    if (ch === "'" || ch === '"') {
      const quote = ch;
      out += ch;
      i += 1;
      while (i < len) {
        if (raw[i] === '\\' && i + 1 < len) {
          out += raw[i] + raw[i + 1];
          i += 2;
          continue;
        }
        out += raw[i];
        if (raw[i] === quote) {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }

    if (ch === '/' && next === '*') {
      out += '  ';
      i += 2;
      while (i < len && !(raw[i] === '*' && raw[i + 1] === '/')) {
        out += raw[i] === '\n' ? '\n' : ' ';
        i += 1;
      }
      if (i < len) {
        out += '  ';
        i += 2;
      }
      continue;
    }

    if ((ch === '/' && next === '/') || (ch === '#' && next !== '[')) {
      while (i < len && raw[i] !== '\n') {
        out += ' ';
        i += 1;
      }
      continue;
    }

    out += ch;
    i += 1;
  }

  return out;
}

/**
 * Extract PHP `include` / `require` file specifiers and local `.php` route links/actions.
 * @param {string} source
 * @returns {Array<{ specifier: string, relation: string }>}
 */
function extractPhpDependencies(source) {
  const cleaned = stripPhpCommentsPreservingNewlines(source);
  const found = [];
  const seen = new Set();

  const addSpec = (rawSpec, relation) => {
    const trimmed = String(rawSpec || '')
      .trim()
      .split(/[?#]/)[0]
      .trim();
    if (!trimmed || /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) return;
    const key = `${relation}:${trimmed}`;
    if (!seen.has(key)) {
      seen.add(key);
      found.push({ specifier: trimmed, relation });
    }
  };

  // Match `require "config.php"`, `include_once('templates/header.php')`,
  // `require_once __DIR__ . '/../common.php'`, `include APPPATH . 'views/head.php'`
  const includePatterns = [
    /\b(?:include|include_once|require|require_once)\s*\(?\s*(?:(?:__DIR__|dirname\s*\(\s*__FILE__\s*\)|APPPATH|APP|BASEPATH)\s*\.\s*)?['"]([^'"]+\.php)['"]\s*\)?/gi
  ];

  for (const regex of includePatterns) {
    for (const match of cleaned.matchAll(regex)) {
      if (match[1]) addSpec(match[1], 'requires');
    }
  }

  // Match multi-page PHP route transitions (`href="update-single.php?id=..."`, `action="create.php"`)
  const routeLinkRe = /\b(?:href|action)\s*=\s*['"]([^'"]*?\.php)(?:\?[^'"]*)?['"]/gi;
  for (const match of cleaned.matchAll(routeLinkRe)) {
    if (match[1]) addSpec(match[1], 'links');
  }

  return found;
}

/**
 * Resolve a PHP `include`/`require` or `.php` route target against `repoFileSet`.
 * @param {string} importerRelFile
 * @param {string} rawSpecifier
 * @param {Set<string>} repoFileSet
 * @returns {string|null}
 */
function resolvePhpDependencyTarget(importerRelFile, rawSpecifier, repoFileSet) {
  const cleanSpec = String(rawSpecifier || '')
    .replace(/\\/g, '/')
    .split(/[?#]/)[0]
    .replace(/^\/+/, '')
    .trim();
  if (!cleanSpec) return null;

  const baseDir = path.posix.dirname(importerRelFile);
  const relJoined = path.posix.normalize(path.posix.join(baseDir, cleanSpec));
  const rootJoined = path.posix.normalize(cleanSpec);

  const candidates = [];
  if (!relJoined.startsWith('..')) {
    candidates.push(relJoined, `${relJoined}.php`);
  }
  if (!rootJoined.startsWith('..')) {
    candidates.push(
      rootJoined,
      `${rootJoined}.php`,
      `public/${rootJoined}`,
      `application/${rootJoined}`,
      `src/${rootJoined}`
    );
  }

  for (const candidate of candidates) {
    if (repoFileSet.has(candidate) && candidate !== importerRelFile) {
      return candidate;
    }
  }
  return null;
}

/**
 * Extract PHP AST declarations (`namespace`, `class`, `interface`, `trait`, `function`)
 * plus deterministic route/module symbols for top-level procedural PHP scripts.
 * @param {string} source
 * @param {string} relFile
 * @returns {Array<{ symbol_name: string, symbol_type: string, start_line: number }>}
 */
function extractPhpFileSymbols(source, relFile) {
  const cleaned = stripPhpCommentsPreservingNewlines(source);
  const lines = cleaned.split(/\r?\n/);
  const symbols = [];
  const seen = new Set();

  const pushSym = (symbolName, symbolType, lineNumber) => {
    const cleanName = String(symbolName || '').trim();
    if (!cleanName || seen.has(cleanName)) return;
    seen.add(cleanName);
    symbols.push({
      symbol_name: cleanName,
      symbol_type: symbolType,
      start_line: lineNumber
    });
  };

  for (let idx = 0; idx < lines.length; idx += 1) {
    const line = lines[idx];
    if (line.length > 2000) continue;
    const lineNo = idx + 1;

    const nsMatch = line.match(/\bnamespace\s+([A-Za-z_\\][A-Za-z0-9_\\]*)\s*;/);
    if (nsMatch) {
      pushSym(nsMatch[1], 'namespace', lineNo);
    }

    const classMatch = line.match(
      /\b(?:(?:abstract|final|readonly)\s+)*(class|interface|trait)\s+([A-Za-z_][A-Za-z0-9_]*)\b/
    );
    if (classMatch) {
      pushSym(classMatch[2], classMatch[1], lineNo);
    }

    const fnMatch = line.match(
      /\bfunction\s+&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/
    );
    if (fnMatch) {
      pushSym(fnMatch[1], 'function', lineNo);
    }
  }

  // Procedural PHP pages (`public/create.php`, `config.php`, `templates/header.php`) often execute
  // top-level statements without declaring functions; emit a deterministic entrypoint symbol.
  if (symbols.length === 0) {
    const baseName = path.posix.basename(relFile, '.php');
    const lowerRel = relFile.toLowerCase();
    const isTemplate = lowerRel.includes('template') || lowerRel.includes('header') || lowerRel.includes('footer');
    const isConfig = lowerRel.includes('config');
    const prefix = isTemplate ? 'template' : isConfig ? 'config' : 'route';
    pushSym(`${prefix}:${baseName}`, prefix, 1);
  }

  return symbols;
}

/**
 * Deterministic `<1ms` PHP-to-Next.js migration & slop hazard scanner mapping legacy PHP
 * constructs to sealed `@krusch/toolkit` Golden Bricks.
 * @param {string} source
 * @param {string} filePath
 * @returns {Array<{ filePath: string, ruleId: string, brickId: string, importPath: string, severity: string, message: string }>}
 */
function auditPhpMigrationFile(source, filePath) {
  const cleaned = stripPhpCommentsPreservingNewlines(source);
  const findings = [];

  const pushFinding = (ruleId, brickId, importPath, message) => {
    findings.push({
      filePath,
      ruleId,
      brickId,
      importPath,
      severity: 'error',
      message
    });
  };

  if (
    /\b(?:round|number_format)\s*\([^;\n]*\$(?:this->)?[A-Za-z0-9_]*(?:price|amount|vat|tax|discount|fee|total|subtotal|cash|pos|tendered|balance)[A-Za-z0-9_]*/i.test(
      cleaned
    ) ||
    /\$(?:this->)?[A-Za-z0-9_]*(?:price|amount|vat|tax|discount|fee|total|subtotal)[A-Za-z0-9_]*\s*=\s*round\s*\(/i.test(
      cleaned
    )
  ) {
    pushFinding(
      'php-float-currency-math',
      'audit-log',
      '@krusch/toolkit/audit-log',
      'Floating-point PHP currency rounding (round(..., 2)) risks sub-cent batch drift during Next.js migration; port to integer-cent largest-remainder allocation (INV-FIN-03) with @krusch/toolkit/audit-log.'
    );
  }

  if (
    /["']\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"'\n]*\$[A-Za-z_]/i.test(cleaned) ||
    /\bmysqli_query\s*\([^;\n]*\$_(?:GET|POST|REQUEST)/i.test(cleaned)
  ) {
    pushFinding(
      'php-raw-sql-interpolation',
      'sqlite',
      '@krusch/toolkit/sqlite',
      'Interpolated PHP variable inside SQL statement risks SQL injection; port to parameterized @krusch/toolkit/sqlite (openSqliteDb) or @krusch/toolkit/pg (createPgPool) queries.'
    );
  }

  if (
    /\bnew\s+PDO\s*\(/.test(cleaned) ||
    /\bmysqli_connect\s*\(/.test(cleaned) ||
    /\becho\b[^;\n]*->getMessage\s*\(\s*\)/.test(cleaned)
  ) {
    pushFinding(
      'php-per-request-pdo-or-sql-leak',
      'sqlite',
      '@krusch/toolkit/sqlite',
      'Per-request PHP DB connection or raw PDOException HTML echo detected; centralize pooled DB access in Next.js server modules with @krusch/toolkit/sqlite or @krusch/toolkit/pg and @krusch/toolkit/http (errorEnvelope).'
    );
  }

  if (/\$_(?:POST|GET|REQUEST)\s*\[/.test(cleaned)) {
    pushFinding(
      'php-unvalidated-superglobal-input',
      'schema',
      '@krusch/toolkit/schema',
      'Untyped PHP $_POST/$_GET superglobal intake; port to Next.js App Router Route Handlers or Server Actions validated with @krusch/toolkit/schema (s, validateSchema).'
    );
  }

  if (
    /\bsession_start\s*\(/.test(cleaned) ||
    /\bmcrypt_create_iv\s*\(/.test(cleaned) ||
    /\b(?:md5|sha1)\s*\(/.test(cleaned)
  ) {
    pushFinding(
      'php-legacy-session-or-weak-crypto',
      'auth',
      '@krusch/toolkit/auth',
      'Stateful PHP session_start() or weak/deprecated crypto (mcrypt/md5/sha1) detected; port to stateless httpOnly JWT sessions via @krusch/toolkit/auth (createAuth).'
    );
  }

  if (
    /\$(?:password|passwd|db_pass|dbpass)\s*=\s*['"][^'"]+['"]/i.test(cleaned) ||
    /\bdefine\s*\(\s*['"]DB_PASS(?:WORD)?['"]\s*,\s*['"][^'"]+['"]\s*\)/i.test(cleaned)
  ) {
    pushFinding(
      'php-hardcoded-db-credentials',
      'config',
      '@krusch/toolkit/config',
      'Hardcoded PHP database credentials in source; externalize server-only configuration via @krusch/toolkit/config (loadProjectConfig, envOr).'
    );
  }

  if (
    /\bSELECT\s+\*\s+FROM\s+[A-Za-z0-9_`]+(?:\s*;|\s*["'])/i.test(cleaned) &&
    !/\bLIMIT\b/i.test(cleaned)
  ) {
    pushFinding(
      'php-unbounded-table-scan',
      'pagination',
      '@krusch/toolkit/pagination',
      'Unbounded SELECT * table scan without cursor limit; port Next.js list routes to HMAC-signed keyset pagination via @krusch/toolkit/pagination (encodeCursor, paginateItems).'
    );
  }

  return findings;
}

/**
 * Extract top-level class, interface, struct, trait, module, and function/method declarations
 * from polyglot enterprise repositories (Java, C#, Go, Ruby, Rust, Kotlin).
 * @param {string} source
 * @param {string} relFile
 * @param {string} ext
 * @returns {Array<{ symbol_name: string, symbol_type: string, start_line: number }>}
 */
function extractPolyglotFileSymbols(source, relFile, ext) {
  const cleaned = stripPhpCommentsPreservingNewlines(source);
  const lines = cleaned.split(/\r?\n/);
  const symbols = [];
  const seen = new Set();

  const pushSym = (symbolName, symbolType, lineNumber) => {
    const cleanName = String(symbolName || '').trim();
    if (!cleanName || seen.has(cleanName) || symbols.length >= 24) return;
    seen.add(cleanName);
    symbols.push({
      symbol_name: cleanName,
      symbol_type: symbolType,
      start_line: lineNumber
    });
  };

  for (let idx = 0; idx < lines.length; idx += 1) {
    const line = lines[idx];
    if (line.length > 2000) continue;
    const lineNo = idx + 1;

    const typeMatch = line.match(
      /\b(class|interface|struct|enum|trait|record|module)\s+([A-Za-z_][A-Za-z0-9_]*)\b/
    );
    if (typeMatch) {
      pushSym(typeMatch[2], typeMatch[1], lineNo);
    }

    const fnMatch =
      line.match(/\b(?:func|fn|def|fun)\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_?!]*)/) ||
      line.match(
        /\b(?:public|protected|private|internal)\s+(?:(?:static|final|virtual|override|async|synchronized)\s+)*(?:[A-Za-z0-9_<>\[\].,?*]+\s+){1,6}([A-Za-z_][A-Za-z0-9_]*)\s*\(/
      );
    if (
      fnMatch &&
      !['if', 'for', 'while', 'switch', 'catch', 'return', 'new'].includes(fnMatch[1])
    ) {
      pushSym(fnMatch[1], 'function', lineNo);
    }
  }

  if (symbols.length === 0) {
    const stem = path.posix.basename(relFile, ext);
    pushSym(`module:${stem}`, 'module', 1);
  }

  return symbols;
}

/**
 * Deterministic `<1ms` polyglot enterprise brownfield hazard scanner (Java, C#, Go, Ruby, Rust, Kotlin)
 * mapping legacy backend patterns to sealed `@krusch/toolkit` Golden Bricks.
 * @param {string} source
 * @param {string} filePath
 * @returns {Array<{ filePath: string, ruleId: string, brickId: string, importPath: string, severity: string, message: string }>}
 */
function auditPolyglotMigrationFile(source, filePath) {
  const cleaned = stripPhpCommentsPreservingNewlines(source);
  const findings = [];

  const pushFinding = (ruleId, brickId, importPath, message) => {
    findings.push({
      filePath,
      ruleId,
      brickId,
      importPath,
      severity: 'error',
      message
    });
  };

  if (
    /\b(?:double|float)\s+[A-Za-z0-9_]*(?:price|amount|fee|tax|vat|total|subtotal|balance|discount|rate)[A-Za-z0-9_]*\b/i.test(
      cleaned
    ) ||
    /\b[A-Za-z0-9_]*(?:price|amount|fee|tax|vat|total|subtotal|balance)[A-Za-z0-9_]*\s*\.\s*round\s*\(\s*2\s*\)/i.test(
      cleaned
    )
  ) {
    pushFinding(
      'polyglot-float-currency-math',
      'audit-log',
      '@krusch/toolkit/audit-log',
      'IEEE-754 float/double currency arithmetic risks sub-cent batch drift; port to integer-cent largest-remainder allocation (INV-FIN-03) with @krusch/toolkit/audit-log.'
    );
  }

  if (
    /"\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"\n]*"\s*\+/i.test(cleaned) ||
    /'\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^'\n]*'\s*\+/i.test(cleaned) ||
    /\b(?:fmt\.Sprintf|String\.format)\s*\(\s*["'`]\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b/i.test(
      cleaned
    ) ||
    /\$"\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"\n]*\{/i.test(cleaned) ||
    /"\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"\n]*#\{/i.test(cleaned)
  ) {
    pushFinding(
      'polyglot-raw-sql-concat',
      'pg',
      '@krusch/toolkit/pg',
      'Interpolated or concatenated SQL query string detected; port to parameterized @krusch/toolkit/pg (createPgPool) or @krusch/toolkit/sqlite (openSqliteDb) queries.'
    );
  }

  if (
    /\b(?:http\.(?:Get|Post|NewRequest)|new\s+HttpClient\s*\(|RestTemplate\b|WebClient\.create|Net::HTTP\.|URI\.open\s*\(|reqwest::get\s*\()/.test(
      cleaned
    )
  ) {
    pushFinding(
      'polyglot-unguarded-outbound-http',
      'security',
      '@krusch/toolkit/security',
      'Direct outbound HTTP client call without DNS-pinned SSRF protection; port outbound calls to @krusch/toolkit/security (safeFetch, validateOutboundUrl).'
    );
  }

  if (
    /\bMessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']\s*\)/i.test(cleaned) ||
    /\b(?:MD5|SHA1)\.Create\s*\(/i.test(cleaned) ||
    /\b(?:md5|sha1)\.(?:New|Sum)\s*\(/.test(cleaned) ||
    /\bDigest::(?:MD5|SHA1)\b/.test(cleaned)
  ) {
    pushFinding(
      'polyglot-weak-crypto-digest',
      'auth',
      '@krusch/toolkit/auth',
      'Legacy MD5/SHA-1 cryptographic digest detected; port authentication and token signing to @krusch/toolkit/auth (createAuth) or SHA-256 HMAC.'
    );
  }

  if (
    /\bSELECT\s+\*\s+FROM\s+[A-Za-z0-9_.`"]+/i.test(cleaned) &&
    !/\b(?:LIMIT|TOP|FETCH\s+FIRST|Pageable)\b/i.test(cleaned)
  ) {
    pushFinding(
      'polyglot-unbounded-select-all',
      'pagination',
      '@krusch/toolkit/pagination',
      'Unbounded SELECT * query without cursor/limit pagination; port list endpoints to @krusch/toolkit/pagination (encodeCursor, paginateItems).'
    );
  }

  return findings;
}

/**
 * Check whether a local path targets a protected OS or credential directory.
 * @param {string} candidatePath
 * @returns {boolean}
 */
function isSensitiveLocalPath(candidatePath) {
  const normalized = path.resolve(candidatePath).replace(/\\/g, '/');
  for (const prefix of SENSITIVE_LOCAL_PREFIXES) {
    if (normalized === prefix || normalized.startsWith(`${prefix}/`)) {
      return true;
    }
  }
  const segments = normalized.split('/').filter(Boolean);
  for (const seg of segments) {
    if (SENSITIVE_SEGMENT_NAMES.has(seg.toLowerCase())) {
      return true;
    }
  }
  return false;
}

/**
 * Race a promise against a short timeout so unreachable remote probes fail fast.
 * @template T
 * @param {Promise<T>} promise
 * @param {number} timeoutMs
 * @returns {Promise<T>}
 */
function withBoundedTimeout(promise, timeoutMs = 1200) {
  let timer = null;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`Remote probe timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

/**
 * Build default billing work order descriptors if caller omits `workOrders`.
 * @param {Set<string>} repoFileSet
 * @returns {Array<object>}
 */
function buildDefaultWorkOrdersIfAbsent(repoFileSet) {
  const defaults = [];
  if (repoFileSet.has('src/fee-engine.js')) {
    defaults.push({
      id: 'WO-101',
      title: 'Fix sub-cent fee rounding drift in fee-engine batch reconciliation',
      priority: 'P0',
      labels: ['INV-FIN-03', 'sox', 'reconciliation'],
      targetFiles: ['src/fee-engine.js']
    });
  }
  if (repoFileSet.has('src/webhook-handler.js')) {
    defaults.push({
      id: 'WO-102',
      title: 'Replace legacy webhook signature check with constant-time HMAC brick',
      priority: 'P1',
      labels: ['webhooks', 'security', 'golden-brick'],
      targetFiles: ['src/webhook-handler.js']
    });
  }
  if (repoFileSet.has('src/invoice-list.js')) {
    defaults.push({
      id: 'WO-103',
      title: 'Add signed keyset cursor pagination to invoice-list endpoint',
      priority: 'P2',
      labels: ['pagination', 'golden-brick'],
      targetFiles: ['src/invoice-list.js']
    });
  }
  return defaults;
}

/**
 * Infer deterministic complexity and frontier eligibility for a Work Order.
 * @param {object} wo
 * @param {number} hop2ReachCount
 * @returns {{ taskClass: string, complexityScore: number, estimatedTokens: number, allowFrontier: boolean }}
 */
function classifyWorkOrderRoutingProfile(wo, hop2ReachCount) {
  const id = String(wo?.id || wo?.workOrderId || '').toUpperCase();
  const haystack = [
    id,
    wo?.title || '',
    wo?.description || '',
    ...(Array.isArray(wo?.labels) ? wo.labels : [])
  ]
    .join(' ')
    .toLowerCase();

  const isMultiHopFinancial =
    id === 'WO-101' ||
    /inv-fin|sox|reconcil|settlement|ledger|penny|sub-cent/.test(haystack) ||
    hop2ReachCount >= 1;

  if (isMultiHopFinancial) {
    return {
      taskClass: 'multi_hop_financial_reconciliation',
      complexityScore: 0.88,
      estimatedTokens: 6400,
      allowFrontier: true
    };
  }

  return {
    taskClass: 'bounded_golden_brick_plumbing',
    complexityScore: 0.22,
    estimatedTokens: 1800,
    allowFrontier: false
  };
}

/**
 * Create the Stage 2 DEADBOLT Planner engine.
 * @param {object} options
 * @param {object} options.stack - KruschStack instance providing `stack.git`
 * @param {object|null} [options.kruschGitClient=null] - Optional remote KruschGit HTTP client
 */
export function createPlannerEngine({ stack, kruschGitClient = null } = {}) {
  if (!stack || !stack.git) {
    throw new Error('createPlannerEngine requires a KruschStack instance with stack.git');
  }

  const breaker = createTierCircuitBreaker({
    failureThreshold: 3,
    cooldownMs: 30_000
  });

  // Snapshot relevant env keys once as a plain JS object to avoid Node C++ process.env FFI traps on hot path
  const cascadeEnvSnapshot = Object.freeze({
    OLLAMA_L1_URL: process.env.OLLAMA_L1_URL || '',
    OLLAMA_L2_URL: process.env.OLLAMA_L2_URL || '',
    COLAB_BURST_URL: process.env.COLAB_BURST_URL || '',
    GEMINI_API_BASE_URL: process.env.GEMINI_API_BASE_URL || '',
    GEMINI_MODEL: process.env.GEMINI_MODEL || ''
  });

  /**
   * Execute a single monomorphic Cascade tier route with nanosecond hrtime measurement.
   * @param {{ complexityScore: number, estimatedTokens: number, allowFrontier: boolean }} profile
   */
  function runMeasuredCascadeSelect(profile) {
    const startNs = process.hrtime.bigint();
    const envelope = selectCascadeTier({
      complexityScore: profile.complexityScore,
      estimatedTokens: profile.estimatedTokens,
      requiresTools: true,
      allowBurst: false,
      allowFrontier: profile.allowFrontier,
      breaker,
      env: cascadeEnvSnapshot,
      tool: 'deadbolt.planner.cascade'
    });
    const elapsedNs = process.hrtime.bigint() - startNs;
    return { envelope, elapsedNs };
  }

  // Warm V8 TurboFan monomorphic IC & hrtime Fast-C-API once at engine construction for <25us hot path
  for (let i = 0; i < 1500; i += 1) {
    runMeasuredCascadeSelect({
      complexityScore: i % 2 === 0 ? 0.22 : 0.88,
      estimatedTokens: i % 2 === 0 ? 1800 : 6400,
      allowFrontier: i % 2 !== 0
    });
  }
  auditBoilerplateText('export const warm = true;\n', 'warm.js');

  /**
   * Build the combined AST symbol + relative import graph across all code files in `repoDir`.
   * @param {string} resolvedRepoDir
   * @param {string} repoName
   */
  function buildRepositoryDependencyModel(resolvedRepoDir, repoName) {
    let indexRes = null;
    try {
      indexRes = stack.git.indexRepo({
        path: resolvedRepoDir,
        repoPath: resolvedRepoDir,
        name: repoName,
        repoName
      });
    } catch {
      indexRes = null;
    }

    const allFiles = collectRepoCodeFiles(resolvedRepoDir, 250);
    let rootTreeEntries = [];
    try {
      const treeRes = stack.git.readTree({ repo: repoName, path: '' });
      rootTreeEntries = Array.isArray(treeRes?.data?.entries) ? treeRes.data.entries : [];
    } catch {
      const topSegments = new Set(allFiles.map((rel) => rel.split('/')[0]).filter(Boolean));
      rootTreeEntries = [...topSegments].map((name) => ({ name, path: name }));
    }

    const repoFileSet = new Set(allFiles);

    // Map each file -> its declared symbols, and build inbound/outbound file dependency maps
    const symbolsByFile = new Map();
    const inboundDependents = new Map(); // targetFile -> Set<callerOrImporterFile>
    const outboundTargets = new Map(); // sourceFile -> Set<importedOrCalledFile>
    const edgeRecords = [];
    const seenEdgeKey = new Set();

    for (const file of allFiles) {
      inboundDependents.set(file, new Set());
      outboundTargets.set(file, new Set());
    }

    const recordDirectedDependency = (dependentFile, targetFile, relation, detail = '') => {
      if (!dependentFile || !targetFile || dependentFile === targetFile) return;
      if (!repoFileSet.has(dependentFile) || !repoFileSet.has(targetFile)) return;

      inboundDependents.get(targetFile).add(dependentFile);
      outboundTargets.get(dependentFile).add(targetFile);

      const key = `${dependentFile}->${targetFile}:${relation}:${detail}`;
      if (!seenEdgeKey.has(key)) {
        seenEdgeKey.add(key);
        edgeRecords.push({
          from: dependentFile,
          to: targetFile,
          relation,
          ...(detail ? { symbol: detail } : {})
        });
      }
    };

    // 1. Walk relative/polyglot imports and PHP `require`/`include` dependencies across repository files
    const phpSourceByFile = new Map();
    const polyglotSourceEntries = [];
    for (const relFile of allFiles) {
      const ext = path.extname(relFile).toLowerCase();
      const abs = path.join(resolvedRepoDir, relFile);
      let content = '';
      try {
        const st = fs.lstatSync(abs);
        if (st.isSymbolicLink() || !st.isFile() || st.size > 262_144) continue;
        const buf = fs.readFileSync(abs);
        if (buf.subarray(0, 4096).includes(0)) continue;
        content = buf.toString('utf8');
      } catch {
        continue;
      }

      if (ext === '.php') {
        phpSourceByFile.set(relFile, content);
        for (const dep of extractPhpDependencies(content)) {
          const resolvedTarget = resolvePhpDependencyTarget(relFile, dep.specifier, repoFileSet);
          if (resolvedTarget) {
            recordDirectedDependency(relFile, resolvedTarget, dep.relation);
          }
        }
        continue;
      }

      polyglotSourceEntries.push({ filePath: relFile, content });
      if (JS_TS_EXTENSIONS.has(ext)) {
        const specifiers = extractRelativeSpecifiers(content);
        for (const spec of specifiers) {
          const resolvedTarget = resolveRelativeImportTarget(relFile, spec, repoFileSet);
          if (resolvedTarget) {
            recordDirectedDependency(relFile, resolvedTarget, 'imports');
          }
        }
      }
    }

    for (const edge of extractPolyglotDependencyEdges(polyglotSourceEntries)) {
      recordDirectedDependency(edge.from, edge.to, 'imports');
    }

    // 2. Walk AST symbols (`stack.git` one-shot map for JS/TS/PY + PHP symbol/call extractor for `.php`)
    let totalSymbols = 0;
    const phpDeclaredSymbolOwner = new Map();
    const indexedSymbolsByFile = loadAllRepoSymbolsByFile(stack, repoName);

    for (const relFile of allFiles) {
      const ext = path.extname(relFile).toLowerCase();
      if (ext === '.php') {
        const phpContent = phpSourceByFile.get(relFile) || '';
        const phpSyms = extractPhpFileSymbols(phpContent, relFile);
        symbolsByFile.set(relFile, phpSyms);
        totalSymbols += phpSyms.length;
        for (const sym of phpSyms) {
          if (
            (sym.symbol_type === 'function' || sym.symbol_type === 'class') &&
            !phpDeclaredSymbolOwner.has(sym.symbol_name)
          ) {
            phpDeclaredSymbolOwner.set(sym.symbol_name, relFile);
          }
        }
        continue;
      }

      const syms = indexedSymbolsByFile.get(normalizeRelPath(relFile)) || [];
      symbolsByFile.set(relFile, syms);
      totalSymbols += syms.length;

      for (const sym of syms) {
        const depRes = stack.git.dependencyGraph({
          repo: repoName,
          symbol: sym.symbol_name
        });
        const inboundCallers = Array.isArray(depRes?.data?.inbound) ? depRes.data.inbound : [];
        for (const caller of inboundCallers) {
          const callerFile = normalizeRelPath(caller.from_file);
          if (callerFile && callerFile !== relFile) {
            recordDirectedDependency(callerFile, relFile, 'calls', sym.symbol_name);
          }
        }
      }
    }

    // Resolve cross-file PHP function & class invocation edges
    if (phpDeclaredSymbolOwner.size > 0) {
      for (const [callerFile, rawPhp] of phpSourceByFile.entries()) {
        const cleanedPhp = stripPhpCommentsPreservingNewlines(rawPhp);
        for (const [symName, ownerFile] of phpDeclaredSymbolOwner.entries()) {
          if (callerFile === ownerFile) continue;
          const escaped = symName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const callRe = new RegExp(`\\b(?:new\\s+${escaped}|${escaped}\\s*(?:\\(|::))`);
          if (callRe.test(cleanedPhp)) {
            const declLineRe = new RegExp(`\\b(?:function|class|interface|trait)\\s+&?\\s*${escaped}\\b`);
            if (!declLineRe.test(cleanedPhp)) {
              recordDirectedDependency(callerFile, ownerFile, 'calls', symName);
            }
          }
        }
      }
    }

    // Identify orchestrator choke-point files (known entrypoints or high fan-out hubs >= 3 local targets)
    const chokePoints = new Set();
    for (const file of allFiles) {
      const outboundCount = outboundTargets.get(file)?.size || 0;
      const inboundCount = inboundDependents.get(file)?.size || 0;
      if (KNOWN_CHOKE_POINT_BASENAMES.has(file) || (outboundCount >= 3 && inboundCount === 0)) {
        chokePoints.add(file);
      }
    }

    return {
      indexRes,
      rootTreeEntries,
      allFiles,
      repoFileSet,
      symbolsByFile,
      totalSymbols,
      inboundDependents,
      outboundTargets,
      edgeRecords,
      chokePoints
    };
  }

  /**
   * Probe optional remote Tier 2A `kruschGitClient` safely with redacted private host labels.
   */
  async function probeRemoteKruschGit() {
    if (!kruschGitClient || typeof kruschGitClient.isConfigured !== 'function' || !kruschGitClient.isConfigured()) {
      return {
        configured: false,
        connected: false,
        healthy: false,
        mode: 'embedded_sqlite_ast'
      };
    }

    const safeBaseUrl = redactEndpointUrl(kruschGitClient.baseUrl);
    try {
      await withBoundedTimeout(Promise.resolve(kruschGitClient.health()), 1200);
      let remoteRepoCount = null;
      if (typeof kruschGitClient.listRepos === 'function') {
        try {
          const reposPayload = await withBoundedTimeout(Promise.resolve(kruschGitClient.listRepos()), 1200);
          const list = Array.isArray(reposPayload?.repos)
            ? reposPayload.repos
            : Array.isArray(reposPayload?.data?.repos)
              ? reposPayload.data.repos
              : Array.isArray(reposPayload)
                ? reposPayload
                : null;
          if (list) remoteRepoCount = list.length;
        } catch {
          remoteRepoCount = null;
        }
      }
      return {
        configured: true,
        connected: true,
        healthy: true,
        mode: 'remote_tier2a_plus_sqlite',
        baseUrl: safeBaseUrl,
        ...(remoteRepoCount !== null ? { remoteRepoCount } : {})
      };
    } catch (err) {
      const scrubbedError = scrubPrivateIpLiterals(
        String(scrubPrivateNetworkStrings(String(err?.message || 'unreachable')))
      );
      return {
        configured: true,
        connected: false,
        healthy: false,
        mode: 'embedded_sqlite_ast_fallback',
        baseUrl: safeBaseUrl,
        error: scrubbedError,
        reason: scrubbedError
      };
    }
  }

  /**
   * Compute 2-hop blast radius, <25us Cascade routing, and parallel Work Order AST leases.
   * @param {object} params
   * @param {string} params.repoDir
   * @param {string} [params.repoName='acme-legacy-billing']
   * @param {string} [params.entryFile='src/fee-engine.js']
   * @param {Array<object>} [params.workOrders=[]]
   */
  async function analyzeBlastRadius({
    repoDir,
    repoName = 'acme-legacy-billing',
    entryFile = 'src/fee-engine.js',
    workOrders = []
  } = {}) {
    if (!repoDir || typeof repoDir !== 'string') {
      return errorEnvelope(
        'INVALID_REPO_DIR',
        'repoDir is required to analyze blast radius',
        null,
        'deadbolt.planner.blast_radius'
      );
    }

    const resolvedRepoDir = path.resolve(repoDir);
    if (isSensitiveLocalPath(resolvedRepoDir)) {
      return errorEnvelope(
        'PATH_BLOCKED',
        'Blast-radius indexing of sensitive system or credential directories is forbidden',
        null,
        'deadbolt.planner.blast_radius'
      );
    }

    let realRepoDir;
    try {
      realRepoDir = fs.realpathSync(resolvedRepoDir);
    } catch {
      return errorEnvelope(
        'DIRECTORY_NOT_FOUND',
        'Target repository directory does not exist',
        { repoName },
        'deadbolt.planner.blast_radius'
      );
    }

    if (isSensitiveLocalPath(realRepoDir)) {
      return errorEnvelope(
        'PATH_BLOCKED',
        'Blast-radius indexing of sensitive system or credential directories is forbidden',
        null,
        'deadbolt.planner.blast_radius'
      );
    }

    let realRepoStat = null;
    try {
      realRepoStat = fs.statSync(realRepoDir);
    } catch {
      realRepoStat = null;
    }
    if (!realRepoStat || !realRepoStat.isDirectory()) {
      return errorEnvelope(
        'DIRECTORY_NOT_FOUND',
        'Target repository directory does not exist or is not a directory',
        { repoName },
        'deadbolt.planner.blast_radius'
      );
    }

    const normalizedEntry = normalizeRelPath(entryFile || 'src/fee-engine.js');
    const model = buildRepositoryDependencyModel(realRepoDir, repoName);
    const {
      indexRes,
      rootTreeEntries,
      allFiles,
      repoFileSet,
      symbolsByFile,
      totalSymbols,
      inboundDependents,
      outboundTargets,
      edgeRecords,
      chokePoints
    } = model;

    // Sort helper placing non-choke-point domain modules ahead of orchestrator choke points
    const sortDomainFirst = (fileList) =>
      [...fileList].sort((a, b) => {
        const aChoke = chokePoints.has(a) ? 1 : 0;
        const bChoke = chokePoints.has(b) ? 1 : 0;
        if (aChoke !== bChoke) return aChoke - bChoke;
        return a.localeCompare(b);
      });

    const rawHop1 = new Set(inboundDependents.get(normalizedEntry) || []);
    rawHop1.delete(normalizedEntry);

    // Keep direct domain callers in hop 1; if an orchestrator choke point is also reachable via hop 1,
    // classify it cleanly at hop 2+ so hop 1 highlights immediate domain dependents.
    const domainHop1 = [...rawHop1].filter((f) => !chokePoints.has(f));
    const hop1Set = new Set(domainHop1.length > 0 ? domainHop1 : [...rawHop1]);

    const parentMap = new Map();
    for (const f1 of hop1Set) {
      parentMap.set(f1, normalizedEntry);
    }

    const hop2Set = new Set();
    for (const f1 of hop1Set) {
      const dependentsOfF1 = inboundDependents.get(f1) || new Set();
      for (const dep of dependentsOfF1) {
        if (dep !== normalizedEntry && !hop1Set.has(dep)) {
          hop2Set.add(dep);
          if (!parentMap.has(dep)) parentMap.set(dep, f1);
        }
      }

      // Also traverse non-choke-point local collaborators invoked by hop-1 services
      if (!chokePoints.has(f1)) {
        const calleesOfF1 = outboundTargets.get(f1) || new Set();
        for (const target of calleesOfF1) {
          if (target !== normalizedEntry && !hop1Set.has(target)) {
            hop2Set.add(target);
            if (!parentMap.has(target)) parentMap.set(target, f1);
          }
        }
      }
    }

    // If a choke point directly imported entryFile and wasn't already added via f1, include it in hop2Set
    for (const directCaller of rawHop1) {
      if (chokePoints.has(directCaller) && !hop1Set.has(directCaller) && !hop2Set.has(directCaller)) {
        hop2Set.add(directCaller);
        const viaHop1 = domainHop1[0] || normalizedEntry;
        parentMap.set(directCaller, viaHop1);
      }
    }

    const hop3Set = new Set();
    for (const f2 of hop2Set) {
      if (chokePoints.has(f2)) continue;
      const dependentsOfF2 = inboundDependents.get(f2) || new Set();
      for (const dep of dependentsOfF2) {
        if (dep !== normalizedEntry && !hop1Set.has(dep) && !hop2Set.has(dep)) {
          hop3Set.add(dep);
          if (!parentMap.has(dep)) parentMap.set(dep, f2);
          if (chokePoints.has(dep)) {
            // Surface orchestrator choke points in hop2Files overview as well as hop3Files
            hop2Set.add(dep);
          }
        }
      }
    }

    const hop1Files = sortDomainFirst(hop1Set);
    const hop2Files = sortDomainFirst(hop2Set);
    const hop3Files = sortDomainFirst(hop3Set);

    const reconstructChain = (leaf) => {
      const chain = [leaf];
      const visited = new Set([leaf]);
      let cur = parentMap.get(leaf);
      while (cur && !visited.has(cur)) {
        chain.unshift(cur);
        visited.add(cur);
        cur = parentMap.get(cur);
      }
      return chain.join(' -> ');
    };

    const hopPaths = hop2Files.map((f2) => reconstructChain(f2));
    if (hopPaths.length === 0 && hop1Files.length > 0) {
      for (const f1 of hop1Files) {
        hopPaths.push(`${normalizedEntry} -> ${f1}`);
      }
    }
    const hopPath = hopPaths[0] || normalizedEntry;

    // Normalize Work Orders (fallback to canonical billing trio when omitted)
    const effectiveWorkOrders =
      Array.isArray(workOrders) && workOrders.length > 0
        ? workOrders
        : buildDefaultWorkOrdersIfAbsent(repoFileSet);

    // Compute Parallel Work Order Disjoint AST Leases
    const reservedSet = new Set();
    for (const cp of chokePoints) {
      reservedSet.add(cp);
    }

    const leases = effectiveWorkOrders.map((wo, idx) => {
      const workOrderId = String(wo?.id || wo?.workOrderId || `WO-${idx + 1}`);
      const rawTargets = Array.isArray(wo?.targetFiles)
        ? wo.targetFiles
        : Array.isArray(wo?.files)
          ? wo.files
          : [];
      const targetFiles = rawTargets.map((f) => normalizeRelPath(f)).filter(Boolean);

      const coneSet = new Set(targetFiles);
      const hop1Deps = new Set();
      const hop2Domain = new Set();
      const touchedChokePoints = new Set();

      for (const tf of targetFiles) {
        if (chokePoints.has(tf)) {
          touchedChokePoints.add(tf);
          reservedSet.add(tf);
        }
        const deps1 = inboundDependents.get(tf) || new Set();
        for (const d1 of deps1) {
          if (chokePoints.has(d1)) {
            touchedChokePoints.add(d1);
            reservedSet.add(d1);
            continue;
          }
          coneSet.add(d1);
          if (!targetFiles.includes(d1)) {
            hop1Deps.add(d1);
          }

          // Track 2-hop non-choke-point reach for complexity classification and cone safety
          const deps2 = inboundDependents.get(d1) || new Set();
          for (const d2 of deps2) {
            if (chokePoints.has(d2)) {
              touchedChokePoints.add(d2);
              reservedSet.add(d2);
            } else if (d2 !== tf) {
              hop2Domain.add(d2);
              coneSet.add(d2);
            }
          }
        }
      }

      // Exclude shared orchestrator choke points from worker lease cones
      for (const cp of chokePoints) {
        if (!targetFiles.includes(cp)) {
          coneSet.delete(cp);
        }
      }

      return {
        workOrderId,
        title: String(wo?.title || workOrderId),
        targetFiles,
        hop1Dependents: [...hop1Deps].sort(),
        hop2Dependents: [...hop2Domain].sort(),
        leaseCone: [...coneSet].sort(),
        reservedChokePoints: [...touchedChokePoints].sort(),
        wave: 1,
        _rawWo: wo
      };
    });

    // Detect pairwise lease cone overlaps and assign deterministic execution waves
    const collisions = [];
    const waveBuckets = []; // Array<{ ids: string[], files: Set<string> }>

    for (const lease of leases) {
      let assignedWaveIdx = -1;
      for (let w = 0; w < waveBuckets.length; w += 1) {
        const bucket = waveBuckets[w];
        const overlaps = lease.leaseCone.some((f) => bucket.files.has(f));
        if (!overlaps) {
          assignedWaveIdx = w;
          break;
        }
      }
      if (assignedWaveIdx === -1) {
        assignedWaveIdx = waveBuckets.length;
        waveBuckets.push({ ids: [], files: new Set() });
      }
      lease.wave = assignedWaveIdx + 1;
      waveBuckets[assignedWaveIdx].ids.push(lease.workOrderId);
      for (const f of lease.leaseCone) {
        waveBuckets[assignedWaveIdx].files.add(f);
      }
    }

    for (let i = 0; i < leases.length; i += 1) {
      for (let j = i + 1; j < leases.length; j += 1) {
        const setA = new Set(leases[i].leaseCone);
        const sharedFiles = leases[j].leaseCone.filter((f) => setA.has(f));
        if (sharedFiles.length > 0) {
          collisions.push({
            workOrders: [leases[i].workOrderId, leases[j].workOrderId],
            sharedFiles
          });
        }
      }
    }

    // Prime CPU instruction cache after SQLite C++ FFI before measuring pure in-process Cascade routing
    if (leases.length > 0) {
      runMeasuredCascadeSelect(
        classifyWorkOrderRoutingProfile(leases[0]._rawWo, leases[0].hop2Dependents.length)
      );
    }

    // Measure <25us in-process Cascade tier routing across Work Orders
    const cascadeRoutes = [];
    let totalRoutingNs = 0n;

    for (const lease of leases) {
      const profile = classifyWorkOrderRoutingProfile(
        lease._rawWo,
        lease.hop2Dependents.length
      );

      const { envelope: routeEnvelope, elapsedNs: routeElapsedNs } = runMeasuredCascadeSelect(profile);
      totalRoutingNs += routeElapsedNs;

      const singleLatencyUs = Number((Number(routeElapsedNs) / 1000).toFixed(3));
      const selected = routeEnvelope.data?.selectedTier || null;
      const chain = Array.isArray(routeEnvelope.data?.candidateChain)
        ? routeEnvelope.data.candidateChain.map((t) => t.id)
        : [];

      cascadeRoutes.push({
        workOrderId: lease.workOrderId,
        title: lease.title,
        taskClass: profile.taskClass,
        complexityScore: profile.complexityScore,
        selectedTier: selected?.id || 'UNAVAILABLE',
        model: selected?.model || selected?.defaultModel || 'unknown',
        provider: selected?.provider || 'unknown',
        candidateTiers: chain,
        reason: routeEnvelope.data?.reason || 'unavailable',
        latencyUs: singleLatencyUs
      });

      delete lease._rawWo;
    }

    const routeCount = Math.max(1, cascadeRoutes.length);
    const routingLatencyUs = Number((Number(totalRoutingNs) / 1000 / routeCount).toFixed(3));
    const totalRoutingLatencyUs = Number((Number(totalRoutingNs) / 1000).toFixed(3));

    const entrySymbols = (symbolsByFile.get(normalizedEntry) || []).map((sym) => ({
      symbolName: sym.symbol_name,
      symbolType: sym.symbol_type,
      signature: sym.signature,
      startLine: sym.start_line,
      endLine: sym.end_line
    }));

    const searchSnapshot = stack.git.searchSymbols({ repo: repoName, query: '*' });
    const symbolGraph = {
      repo: repoName,
      totalFiles: allFiles.length,
      totalSymbols,
      sampledSymbols: Array.isArray(searchSnapshot?.data?.symbols)
        ? searchSnapshot.data.symbols.length
        : totalSymbols,
      rootEntries: rootTreeEntries.length,
      indexedCommit: indexRes?.data?.head_commit || 'working-tree',
      entrySymbols,
      edges: edgeRecords
    };

    const chokePointReserved = [...reservedSet].sort();
    const parallelLeases = {
      canRunInParallel: collisions.length === 0 && leases.length > 1,
      disjoint: collisions.length === 0,
      chokePointReserved,
      collisions,
      waves: waveBuckets.map((b) => b.ids),
      leases
    };

    const remoteKruschGit = await probeRemoteKruschGit();

    const summary = `Mapped 2-hop blast radius from ${normalizedEntry} (${hop1Files.length} hop-1, ${hop2Files.length} hop-2; ${hopPath}) with ${routingLatencyUs}us cascade routing.`;

    return okEnvelope('deadbolt.planner.blast_radius', summary, {
      entryFile: normalizedEntry,
      hop1Files,
      hop2Files,
      hop3Files,
      hopPath,
      hopPaths,
      symbolGraph,
      cascadeRoutes,
      routingLatencyUs,
      totalRoutingLatencyUs,
      parallelLeases,
      remoteKruschGit
    });
  }

  /**
   * Scan any validated public GitHub repository URL or safe local directory path.
   * @param {object} params
   * @param {string} params.repoUrlOrPath
   * @param {number} [params.maxFiles=60]
   * @param {string} [params.hintedFile='']
   */
  async function scanExternalRepository({ repoUrlOrPath, maxFiles = 60, hintedFile = '' } = {}) {
    const startNs = process.hrtime.bigint();
    const rawTarget = String(repoUrlOrPath || '').trim();

    if (!rawTarget) {
      return errorEnvelope(
        'INVALID_SCAN_TARGET',
        'Repository URL or local directory path is required',
        null,
        'deadbolt.planner.repo_scan'
      );
    }

    const safeMaxFiles = Math.max(1, Math.min(200, Math.trunc(Number(maxFiles) || 60)));
    const normalizedInput = normalizeGitHubRepoInput(rawTarget);
    let effectiveHintedFile = normalizeRelPath(hintedFile || normalizedInput.hintedFile || '');

    let tempCloneDir = null;
    let scanRoot = '';
    const scanRepoName = `scan-${crypto.randomUUID().slice(0, 8)}`;
    let localDisplayName = 'scanned-repo';
    let didIndexScanRepo = false;

    try {
      if (normalizedInput.isRemoteCandidate) {
        const urlCheck = await validateOutboundUrl(normalizedInput.candidateUrl, {
          allowedProtocols: ['https:'],
          allowedHosts: ['github.com', 'www.github.com'],
          tool: 'deadbolt.planner.repo_scan'
        });

        if (!urlCheck.ok) {
          return errorEnvelope(
            'SSRF_BLOCKED',
            urlCheck.error?.message || 'Outbound repository URL blocked by SSRF guard',
            urlCheck.error?.details ?? { target: rawTarget },
            'deadbolt.planner.repo_scan'
          );
        }

        if (
          normalizedInput.invalidGitHubPath ||
          !normalizedInput.repoSlug ||
          !normalizedInput.cleanHttpsUrl
        ) {
          return errorEnvelope(
            'INVALID_GITHUB_REPO_PATH',
            'GitHub URL must reference a valid https://github.com/<owner>/<repo> path',
            { target: rawTarget },
            'deadbolt.planner.repo_scan'
          );
        }

        const { repoSlug, cleanHttpsUrl } = normalizedInput;

        tempCloneDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deadbolt-scan-'));
        try {
          await execFileAsync(
            'git',
            [
              '-c',
              'credential.helper=',
              '-c',
              'core.askPass=',
              '-c',
              'core.symlinks=false',
              '-c',
              'protocol.file.allow=never',
              '-c',
              'filter.lfs.smudge=',
              '-c',
              'filter.lfs.process=',
              '-c',
              'filter.lfs.required=false',
              'clone',
              '--depth',
              '1',
              '--single-branch',
              '--no-tags',
              '--filter=blob:limit=256k',
              '--',
              cleanHttpsUrl,
              tempCloneDir
            ],
            {
              timeout: 12_000,
              killSignal: 'SIGKILL',
              maxBuffer: 8 * 1024 * 1024,
              env: {
                PATH: process.env.PATH || '/usr/bin:/bin',
                HOME: os.tmpdir(),
                GIT_TERMINAL_PROMPT: '0',
                GIT_ASKPASS: '',
                SSH_ASKPASS: '',
                GIT_CONFIG_NOSYSTEM: '1'
              }
            }
          );
        } catch (cloneErr) {
          const scrubbedCloneMsg = scrubPrivateIpLiterals(
            String(scrubPrivateNetworkStrings(String(cloneErr?.message || 'clone error')))
          );
          return errorEnvelope(
            'GIT_CLONE_FAILED',
            `Shallow git clone failed for ${repoSlug}: ${scrubbedCloneMsg}`,
            { repo: repoSlug },
            'deadbolt.planner.repo_scan'
          );
        }
        scanRoot = tempCloneDir;
      } else {
        const resolvedCandidate = path.resolve(rawTarget);
        if (isSensitiveLocalPath(resolvedCandidate)) {
          return errorEnvelope(
            'PATH_BLOCKED',
            'Scanning sensitive system or credential directories is forbidden',
            null,
            'deadbolt.planner.repo_scan'
          );
        }

        let realDir = '';
        try {
          realDir = fs.realpathSync(resolvedCandidate);
          if (!fs.statSync(realDir).isDirectory()) {
            return errorEnvelope(
              'DIRECTORY_NOT_FOUND',
              'Local repository path does not exist or is not a directory',
              null,
              'deadbolt.planner.repo_scan'
            );
          }
        } catch {
          return errorEnvelope(
            'DIRECTORY_NOT_FOUND',
            'Local repository path does not exist or is not a directory',
            null,
            'deadbolt.planner.repo_scan'
          );
        }

        if (isSensitiveLocalPath(realDir)) {
          return errorEnvelope(
            'PATH_BLOCKED',
            'Resolved symlink targets a sensitive directory and was blocked',
            null,
            'deadbolt.planner.repo_scan'
          );
        }

        scanRoot = realDir;
        localDisplayName = path.basename(realDir) || 'local-scan';
      }

      const scanStartNs = process.hrtime.bigint();
      const cloneElapsedMs = Number((Number(scanStartNs - startNs) / 1e6).toFixed(3));
      const {
        files: relFiles,
        resolvedHinted,
        hintBlocked
      } = collectPrioritizedRepoFiles(scanRoot, safeMaxFiles, {
        hintedFile: effectiveHintedFile,
        walkCap: MAX_REPO_WALK_CANDIDATES
      });
      if (hintBlocked) {
        effectiveHintedFile = '';
      } else if (resolvedHinted) {
        effectiveHintedFile = resolvedHinted;
      }
      const repoFileSet = new Set(relFiles);
      const fileEntries = [];
      const dependencyPreview = [];
      const seenPreviewEdge = new Set();
      const dependencyEdges = [];
      const seenMergedEdge = new Set();
      const phpSymbolsByFile = new Map();
      const polyglotSymbolsByFile = new Map();
      const extraFindings = [];
      let phpSymbolTotal = 0;

      const pushPreviewEdge = (from, to, relation = 'imports') => {
        if (!from || !to || from === to) return;
        const previewKey = `${from}->${to}:${relation}`;
        if (!seenPreviewEdge.has(previewKey) && dependencyPreview.length < 60) {
          seenPreviewEdge.add(previewKey);
          dependencyPreview.push({ from, to, relation, type: 'IMPORTS' });
        }
        const mergedKey = `${from}->${to}`;
        if (!seenMergedEdge.has(mergedKey)) {
          seenMergedEdge.add(mergedKey);
          dependencyEdges.push({ from, to, type: 'IMPORTS', relation });
        }
      };

      for (const relFile of relFiles) {
        const abs = path.join(scanRoot, relFile);
        let content = '';
        try {
          const st = fs.lstatSync(abs);
          if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_SCANNABLE_FILE_BYTES) continue;
          const buf = fs.readFileSync(abs);
          if (buf.subarray(0, 4096).includes(0)) continue;
          content = buf.toString('utf8');
        } catch {
          continue;
        }
        fileEntries.push({
          filePath: relFile,
          content
        });

        const ext = path.extname(relFile).toLowerCase();
        if (ext === '.php') {
          const phpSyms = extractPhpFileSymbols(content, relFile);
          phpSymbolsByFile.set(relFile, phpSyms);
          phpSymbolTotal += phpSyms.length;
          extraFindings.push(...auditPhpMigrationFile(content, relFile));

          for (const dep of extractPhpDependencies(content)) {
            const target = resolvePhpDependencyTarget(relFile, dep.specifier, repoFileSet);
            if (target) {
              pushPreviewEdge(relFile, target, dep.relation);
            }
          }
        } else if (POLYGLOT_EXTENSIONS.has(ext)) {
          const polySyms = extractPolyglotFileSymbols(content, relFile, ext);
          polyglotSymbolsByFile.set(relFile, polySyms);
          extraFindings.push(...auditPolyglotMigrationFile(content, relFile));
        } else if (JS_TS_EXTENSIONS.has(ext)) {
          for (const spec of extractRelativeSpecifiers(content)) {
            const target = resolveRelativeImportTarget(relFile, spec, repoFileSet);
            if (target) {
              pushPreviewEdge(relFile, target, 'imports');
            }
          }
        }
      }

      const scannedFileSet = new Set(fileEntries.map((e) => e.filePath));
      for (const polyEdge of extractPolyglotDependencyEdges(fileEntries)) {
        if (scannedFileSet.has(polyEdge.from) && scannedFileSet.has(polyEdge.to)) {
          pushPreviewEdge(polyEdge.from, polyEdge.to, 'imports');
        }
      }

      const boundedIndexDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deadbolt-bounded-idx-'));
      let indexRes = null;
      try {
        for (const entry of fileEntries) {
          const destAbs = path.resolve(boundedIndexDir, entry.filePath);
          if (destAbs.startsWith(boundedIndexDir + path.sep)) {
            fs.mkdirSync(path.dirname(destAbs), { recursive: true });
            fs.writeFileSync(destAbs, entry.content, 'utf8');
          }
        }
        didIndexScanRepo = true;
        indexRes = stack.git.indexRepo({
          path: boundedIndexDir,
          repoPath: boundedIndexDir,
          name: scanRepoName,
          repoName: scanRepoName
        });
      } finally {
        if (boundedIndexDir) {
          try {
            fs.rmSync(boundedIndexDir, { recursive: true, force: true });
          } catch {
            // Best-effort cleanup of bounded index directory
          }
        }
      }

      const indexedSymbolsByFile = loadAllRepoSymbolsByFile(stack, scanRepoName);

      // Supplement dependencyEdges with AST symbol call/import edges from stack.git
      if (stack?.db?.prepare && indexedSymbolsByFile.size > 0) {
        const symbolOwners = new Map();
        for (const [ownerFile, syms] of indexedSymbolsByFile.entries()) {
          if (!scannedFileSet.has(ownerFile)) continue;
          for (const sym of syms) {
            const name = sym?.symbol_name;
            if (!name) continue;
            if (!symbolOwners.has(name)) symbolOwners.set(name, new Set());
            symbolOwners.get(name).add(ownerFile);
          }
        }
        try {
          const gitEdgeRows = stack.db
            .prepare('SELECT from_file, to_symbol, edge_type FROM git_edges WHERE repo_name = ?')
            .all(scanRepoName);
          for (const row of gitEdgeRows) {
            const fromFile = normalizeRelPath(row?.from_file);
            if (!fromFile || !scannedFileSet.has(fromFile)) continue;
            const owners = symbolOwners.get(row?.to_symbol);
            if (!owners || owners.size === 0 || owners.size > 3) continue;
            for (const targetOwner of owners) {
              if (targetOwner !== fromFile && scannedFileSet.has(targetOwner)) {
                pushPreviewEdge(fromFile, targetOwner, row?.edge_type || 'calls');
              }
            }
          }
        } catch {
          // Ignore optional git_edges supplement failure
        }
      }

      let fallbackPolyglotSymbols = 0;
      for (const [relFile, polySyms] of polyglotSymbolsByFile.entries()) {
        const indexedSyms = indexedSymbolsByFile.get(normalizeRelPath(relFile)) || [];
        if (indexedSyms.length === 0) {
          fallbackPolyglotSymbols += polySyms.length;
        }
      }

      // Compute inDegree, outDegree, and 2-hop blast-radius metadata from merged deduplicated dependencyEdges
      const inboundByFile = new Map();
      const outboundByFile = new Map();
      for (const entry of fileEntries) {
        inboundByFile.set(entry.filePath, new Set());
        outboundByFile.set(entry.filePath, new Set());
      }
      for (const edge of dependencyEdges) {
        if (!scannedFileSet.has(edge.from) || !scannedFileSet.has(edge.to) || edge.from === edge.to) {
          continue;
        }
        outboundByFile.get(edge.from)?.add(edge.to);
        inboundByFile.get(edge.to)?.add(edge.from);
      }

      const inDegreeByFile = {};
      const outDegreeByFile = {};
      const hop1ByFile = new Map();
      const hop2ByFile = new Map();
      let connectedFileCount = 0;

      for (const entry of fileEntries) {
        const fp = entry.filePath;
        const hop1 = [...(inboundByFile.get(fp) || [])].sort(compareCodePathsAlpha);
        const hop1Set = new Set(hop1);
        const hop2Set = new Set();
        for (const h1 of hop1) {
          for (const h2 of inboundByFile.get(h1) || []) {
            if (h2 !== fp && !hop1Set.has(h2)) {
              hop2Set.add(h2);
            }
          }
        }
        const hop2 = [...hop2Set].sort(compareCodePathsAlpha);
        const inDeg = hop1.length;
        const outDeg = outboundByFile.get(fp)?.size || 0;
        if (inDeg > 0 || outDeg > 0) connectedFileCount += 1;

        inDegreeByFile[fp] = inDeg;
        outDegreeByFile[fp] = outDeg;
        hop1ByFile.set(fp, hop1);
        hop2ByFile.set(fp, hop2);
      }

      const topFiles = fileEntries.slice(0, 15).map((entry) => {
        const fp = entry.filePath;
        const ext = path.extname(fp).toLowerCase();
        const syms =
          ext === '.php'
            ? phpSymbolsByFile.get(fp) || []
            : (() => {
                const indexed = indexedSymbolsByFile.get(normalizeRelPath(fp)) || [];
                if (indexed.length > 0) return indexed;
                return polyglotSymbolsByFile.get(fp) || [];
              })();
        const hop1Dependents = hop1ByFile.get(fp) || [];
        const hop2Dependents = hop2ByFile.get(fp) || [];

        return {
          filePath: fp,
          lineCount: entry.content.split(/\r?\n/).length,
          symbolCount: syms.length,
          symbols: syms.slice(0, 8).map((s) => s.symbol_name),
          inDegree: inDegreeByFile[fp] || 0,
          outDegree: outDegreeByFile[fp] || 0,
          hop1Dependents,
          hop2Dependents,
          blastRadiusCount: hop1Dependents.length + hop2Dependents.length
        };
      });

      const hubFiles = [...fileEntries]
        .map((entry) => {
          const fp = entry.filePath;
          const hop1 = hop1ByFile.get(fp) || [];
          const hop2 = hop2ByFile.get(fp) || [];
          return {
            filePath: fp,
            inDegree: inDegreeByFile[fp] || 0,
            outDegree: outDegreeByFile[fp] || 0,
            blastRadiusCount: hop1.length + hop2.length
          };
        })
        .filter((item) => item.inDegree > 0 || item.outDegree > 0)
        .sort(
          (a, b) =>
            b.inDegree - a.inDegree ||
            b.blastRadiusCount - a.blastRadiusCount ||
            b.outDegree - a.outDegree ||
            compareCodePathsAlpha(a.filePath, b.filePath)
        )
        .slice(0, 10);

      const EXT_LIB_AUDIT_PREFIX = '__deadbolt_ext__/';
      const EXT_LIB_AUDIT_PREFIX_STRIP_RE = /^__deadbolt_ext__\//;
      const jsPyEntries = fileEntries
        .filter((entry) => {
          const ext = path.extname(entry.filePath).toLowerCase();
          return ext !== '.php' && !POLYGLOT_EXTENSIONS.has(ext);
        })
        .map((entry) =>
          /^lib(?:-py)?(?:\/|$)/i.test(entry.filePath)
            ? { ...entry, filePath: `${EXT_LIB_AUDIT_PREFIX}${entry.filePath}` }
            : entry
        );
      const coverage = scoreLegoBrickCoverage(jsPyEntries);
      const rawBaseAudit = coverage.data;
      const baseAudit = {
        ...rawBaseAudit,
        findings: (rawBaseAudit.findings || []).map((finding) => ({
          ...finding,
          filePath: String(finding.filePath || '').replace(EXT_LIB_AUDIT_PREFIX_STRIP_RE, '')
        }))
      };
      const mergedFindings = [...baseAudit.findings, ...extraFindings];
      const flaggedFileSet = new Set(mergedFindings.map((item) => item.filePath));
      const recommendedSet = new Set(baseAudit.recommendedBrickIds || []);
      for (const item of extraFindings) {
        if (item.brickId) recommendedSet.add(item.brickId);
      }
      const totalSlopCount = mergedFindings.length;
      const totalTouchpoints = baseAudit.sealedTouchpoints + totalSlopCount;
      const mergedCoverageRatio =
        totalTouchpoints === 0
          ? 1
          : Number((baseAudit.sealedTouchpoints / totalTouchpoints).toFixed(4));

      const mergedSlopAudit = {
        ...baseAudit,
        scannedFiles: fileEntries.length,
        cleanFiles: Math.max(0, fileEntries.length - flaggedFileSet.size),
        flaggedFiles: flaggedFileSet.size,
        slopFindingCount: totalSlopCount,
        recommendedBrickIds: [...recommendedSet].sort(),
        sealedCoverageRatio: mergedCoverageRatio,
        breakerTripped: totalSlopCount > 0,
        findings: mergedFindings
      };

      const symbolCount =
        Number(indexRes?.data?.symbols_indexed ?? 0) + phpSymbolTotal + fallbackPolyglotSymbols;
      const elapsedMs = Number((Number(process.hrtime.bigint() - scanStartNs) / 1e6).toFixed(3));
      const displayTarget = normalizedInput.isRemoteCandidate
        ? normalizedInput.displayTarget
        : localDisplayName;

      const summary = `Scanned ${fileEntries.length} file(s) and ${symbolCount} AST symbol(s) in ${displayTarget} (${mergedSlopAudit.slopFindingCount} slop finding(s), ${dependencyEdges.length} dependency edge(s), ${elapsedMs}ms).`;

      return okEnvelope('deadbolt.planner.repo_scan', summary, {
        target: displayTarget,
        hintedFile: effectiveHintedFile,
        scannedFiles: fileEntries.length,
        scannedFilePaths: fileEntries.map((entry) => entry.filePath),
        symbolCount,
        topFiles,
        dependencyEdges,
        dependencyEdgeCount: dependencyEdges.length,
        dependencyPreview,
        inDegreeByFile,
        outDegreeByFile,
        blastRadius: {
          edgeCount: dependencyEdges.length,
          connectedFiles: connectedFileCount,
          hubFiles
        },
        slopAudit: mergedSlopAudit,
        elapsedMs,
        cloneElapsedMs
      });
    } finally {
      if (didIndexScanRepo && stack?.db?.prepare) {
        try {
          stack.db.prepare('DELETE FROM git_symbols WHERE repo_name = ?').run(scanRepoName);
          stack.db.prepare('DELETE FROM git_edges WHERE repo_name = ?').run(scanRepoName);
          stack.db.prepare('DELETE FROM git_repositories WHERE name = ?').run(scanRepoName);
        } catch {
          // Best-effort cleanup of ephemeral SQLite scan rows
        }
      }
      if (tempCloneDir) {
        try {
          fs.rmSync(tempCloneDir, { recursive: true, force: true });
        } catch {
          // Best-effort cleanup of ephemeral clone directory
        }
      }
    }
  }

  return {
    analyzeBlastRadius,
    scanExternalRepository
  };
}
