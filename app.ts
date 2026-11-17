// GitHub-compatible forge: git smart HTTP + REST v3 + GraphQL + MCP, one shared store.
// Node 22 stdlib only. No wall clock, no randomness in any response.
// Viewer login is the scenario's deterministic viewer (wire.ts SCENARIO_SEED): adaiversen.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const EPOCH = 1700000000;
const MERGED_AT = '2025-01-01T00:00:00.000Z';
const IDENTITY = 'Conformance <conformance@make.fun>';
const ZERO = '0'.repeat(40);
const JSON_TYPE = 'application/json; charset=utf-8';

function tokenExpected(): string { return process.env.MAKEFUN_SHOP_TOKEN ?? ''; }
function authed(req: IncomingMessage): boolean {
  const h = req.headers.authorization ?? '';
  const exp = tokenExpected();
  if (exp !== '') return h === `Bearer ${exp}`;
  return h !== '' && h.startsWith('Bearer ');
}

// ---------- small utils ----------
function sha1hex(data: Buffer): string { return createHash('sha1').update(data).digest('hex'); }
function b64e(s: string): string { return Buffer.from(s, 'utf8').toString('base64'); }
function b64d(s: string): string { try { return Buffer.from(s, 'base64').toString('utf8'); } catch { return ''; } }
function b64encBuf(b: Buffer): string { return b.toString('base64'); }
function cmpBuf(a: Buffer, b: Buffer): number { return Buffer.compare(a, b); }
function isOid(s: string): boolean { return /^[0-9a-f]{40}$/.test(s); }

// pkt-line
function pkt(data: string | Buffer): Buffer {
  const body = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}
const FLUSH = Buffer.from('0000', 'ascii');
const DELIM = Buffer.from('0001', 'ascii');
type Pkt = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'end' };
function parsePkts(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('bad pkt-line header');
    const len = parseInt(head, 16);
    if (len === 0) { out.push({ kind: 'flush' }); off += 4; continue; }
    if (len === 1) { out.push({ kind: 'delim' }); off += 4; continue; }
    if (len === 2) { out.push({ kind: 'end' }); off += 4; continue; }
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    out.push({ kind: 'data', payload: Buffer.from(buf.subarray(off + 4, off + len)) });
    off += len;
  }
  return out;
}
function pktLines(pkts: Pkt[]): string[] {
  const out: string[] = [];
  for (const p of pkts) if (p.kind === 'data') out.push(p.payload.toString('utf8'));
  return out;
}

// ---------- store ----------
type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface ObjRec { type: ObjType; data: Buffer; deflated?: Buffer }
interface CommentRec { id: number; body: string }
interface IssueRec { id: number; number: number; title: string; body: string; state: 'open' | 'closed'; labels: { name: string }[]; comments: CommentRec[] }
interface PrRec {
  id: number; number: number; title: string; body: string; state: 'open' | 'closed';
  merged: boolean; merged_at: string | null; merge_commit_sha: string | null;
  head: { ref: string; sha: string }; base: { ref: string; sha: string };
  comments: CommentRec[];
}
interface Repo {
  id: number; name: string; owner: string; priv: boolean; description: string;
  refs: Map<string, string>; objects: Map<string, ObjRec>;
  labels: Map<string, { name: string; color: string }>;
  issues: IssueRec[]; prs: PrRec[]; nextIssue: number; nextPr: number; order: number;
}
const repos = new Map<string, Repo>();
let nextRepoId = 1;
let nextEntityId = 1;
let reqCounter = 0;
let repoOrder = 0;
function repoKey(owner: string, name: string): string { return `${owner}/${name}`; }
function getRepo(owner: string, name: string): Repo | undefined { return repos.get(repoKey(owner, name)); }
function gid(kind: string, rest: string): string { return b64e(`${kind}:${rest}`); }
function repoGid(r: Repo): string { return gid('Repository', String(r.id)); }
function issueGid(r: Repo, n: number): string { return gid('Issue', `${r.id}:${n}`); }
function prGid(r: Repo, n: number): string { return gid('PullRequest', `${r.id}:${n}`); }
function commentGid(r: Repo, id: number): string { return gid('IssueComment', `${r.id}:${id}`); }

// ---------- git objects ----------
function hashObject(type: ObjType, data: Buffer): string {
  const h = createHash('sha1');
  h.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  h.update(data);
  return h.digest('hex');
}
function storeObj(r: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!r.objects.has(oid)) r.objects.set(oid, { type, data });
  return oid;
}
function getObj(r: Repo, oid: string): ObjRec | undefined { return r.objects.get(oid); }
interface TreeEntry { mode: string; name: string; oid: string }
function parseTree(data: Buffer): TreeEntry[] {
  const out: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp + 1);
    if (sp < 0 || nul < 0 || nul + 21 > data.length) throw new Error('bad tree');
    out.push({ mode: data.subarray(off, sp).toString('ascii'), name: data.subarray(sp + 1, nul).toString('utf8'), oid: data.subarray(nul + 1, nul + 21).toString('hex') });
    off = nul + 21;
  }
  return out;
}
function cmpTreeName(a: TreeEntry, b: TreeEntry): number {
  const l = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const rr = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(l, rr);
}
function buildTreeBytes(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(cmpTreeName);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
interface CommitView { tree: string; parents: string[]; author: string; committer: string; message: string }
function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = ''; const parents: string[] = []; let author = ''; let committer = '';
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const k = sp < 0 ? line : line.slice(0, sp);
    const v = sp < 0 ? '' : line.slice(sp + 1);
    if (k === 'tree') tree = v; else if (k === 'parent') parents.push(v);
    else if (k === 'author') author = v; else if (k === 'committer') committer = v;
  }
  return { tree, parents, author, committer, message };
}
function makeCommit(r: Repo, tree: string, parents: string[], message: string): string {
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${IDENTITY} ${EPOCH} +0000`, `committer ${IDENTITY} ${EPOCH} +0000`, '');
  const data = Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
  return storeObj(r, 'commit', data);
}
function parseTag(data: Buffer): { object: string; type: string; tag: string; tagger: string; message: string } {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const m = new Map<string, string>();
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    if (sp > 0) m.set(line.slice(0, sp), line.slice(sp + 1));
  }
  return { object: m.get('object') ?? '', type: m.get('type') ?? '', tag: m.get('tag') ?? '', tagger: m.get('tagger') ?? '', message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8') };
}
// flatten a tree to path -> {oid, mode}
function flattenTree(r: Repo, treeOid: string, prefix: string, out: Map<string, { oid: string; mode: string }>): void {
  const obj = getObj(r, treeOid);
  if (!obj || obj.type !== 'tree') return;
  for (const e of parseTree(obj.data)) {
    const p = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.mode === '40000') flattenTree(r, e.oid, p, out);
    else out.set(p, { oid: e.oid, mode: e.mode });
  }
}
function treeOfCommit(r: Repo, commitOid: string): string {
  const o = getObj(r, commitOid);
  if (!o || o.type !== 'commit') return '';
  return parseCommit(o.data).tree;
}
// rebuild nested trees from flat path->blobOid map; returns root tree oid
function rebuildTree(r: Repo, files: Map<string, string>): string {
  interface Node { files: Map<string, string>; dirs: Map<string, Node> }
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, oid] of files) {
    const parts = path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const seg = parts[i] as string;
      let child = node.dirs.get(seg);
      if (!child) { child = { files: new Map(), dirs: new Map() }; node.dirs.set(seg, child); }
      node = child;
    }
    node.files.set(parts[parts.length - 1] as string, oid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObj(r, 'tree', buildTreeBytes(entries));
  };
  return build(root);
}
function resolveRef(r: Repo, ref: string | undefined): string {
  if (!ref) return r.refs.get('refs/heads/main') ?? '';
  if (isOid(ref)) return ref;
  if (ref.startsWith('refs/heads/')) return r.refs.get(ref) ?? '';
  const tip = r.refs.get(`refs/heads/${ref}`);
  if (tip) return tip;
  if (isOid(ref)) return ref;
  return '';
}
// reachability closure. depthLimit: max commit generations (undefined = all).
// cutoff: commit oids whose parents are not traversed (shallow boundaries held by client).
function closure(r: Repo, roots: string[], depthLimit?: number, cutoff?: Set<string>): Set<string> {
  const seen = new Set<string>();
  const walkTree = (treeOid: string): void => {
    if (seen.has(treeOid)) return;
    const o = getObj(r, treeOid);
    if (!o || o.type !== 'tree') return;
    seen.add(treeOid);
    for (const e of parseTree(o.data)) {
      if (e.mode === '160000') continue;
      if (e.mode === '40000') walkTree(e.oid);
      else seen.add(e.oid);
    }
  };
  const walkCommit = (oid: string, depth: number): void => {
    if (seen.has(oid)) return;
    const o = getObj(r, oid);
    if (!o) return;
    if (o.type === 'tag') {
      seen.add(oid);
      const t = parseTag(o.data);
      if (t.object) { const to = getObj(r, t.object); if (to?.type === 'commit') walkCommit(t.object, depth); else if (to) seen.add(t.object); }
      return;
    }
    if (o.type !== 'commit') { seen.add(oid); return; }
    seen.add(oid);
    const c = parseCommit(o.data);
    walkTree(c.tree);
    if (cutoff && cutoff.has(oid)) return;
    if (depthLimit !== undefined && depth + 1 >= depthLimit) return;
    for (const p of c.parents) walkCommit(p, depth + 1);
  };
  for (const root of roots) {
    if (!isOid(root)) continue;
    const o = getObj(r, root);
    if (!o) continue;
    if (o.type === 'commit' || o.type === 'tag') walkCommit(root, 0);
    else if (o.type === 'tree') walkTree(root);
    else seen.add(root);
  }
  return seen;
}
// boundary commits at the depth limit (shallow boundaries of a depth-limited closure)
function boundaryCommits(r: Repo, roots: string[], depthLimit: number): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const walk = (oid: string, depth: number): void => {
    if (seen.has(oid)) return;
    const o = getObj(r, oid);
    if (!o || o.type !== 'commit') return;
    seen.add(oid);
    if (depth + 1 >= depthLimit) { out.push(oid); return; }
    for (const p of parseCommit(o.data).parents) walk(p, depth + 1);
  };
  for (const root of roots) if (isOid(root)) walk(root, 0);
  return out;
}
function isDescendant(r: Repo, cand: string, base: string): boolean {
  if (cand === base) return true;
  const seen = new Set<string>();
  const stack = [cand];
  let guard = 0;
  while (stack.length && guard < 10000) {
    guard++;
    const oid = stack.pop() as string;
    if (oid === base) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const o = getObj(r, oid);
    if (!o || o.type !== 'commit') continue;
    for (const p of parseCommit(o.data).parents) stack.push(p);
  }
  return false;
}
// tree diff: path -> {kind, baseOid?, headOid?}
function treeDiff(r: Repo, baseTree: string, headTree: string): Map<string, { base?: string; head?: string }> {
  const b = new Map<string, { oid: string; mode: string }>();
  const h = new Map<string, { oid: string; mode: string }>();
  if (baseTree) flattenTree(r, baseTree, '', b);
  if (headTree) flattenTree(r, headTree, '', h);
  const out = new Map<string, { base?: string; head?: string }>();
  for (const [p, v] of b) out.set(p, { base: v.oid });
  for (const [p, v] of h) {
    const e = out.get(p);
    if (e) e.head = v.oid; else out.set(p, { head: v.oid });
  }
  for (const [p, e] of [...out]) if (e.base === e.head) out.delete(p);
  return out;
}

// ---------- pack ----------
function deltaApply(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVar = (): number => {
    let v = 0; let s = 0;
    for (;;) { const b = delta[off++] as number; v |= (b & 0x7f) << s; s += 7; if (!(b & 0x80)) break; }
    return v;
  };
  const srcSize = readVar();
  const tgtSize = readVar();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const parts: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off++] as number;
    if (op & 0x80) {
      let cpOff = 0; let cpSize = 0;
      for (let i = 0; i < 4; i++) if (op & (1 << i)) cpOff |= (delta[off++] as number) << (8 * i);
      for (let i = 0; i < 3; i++) if (op & (0x10 << i)) cpSize |= (delta[off++] as number) << (8 * i);
      if (cpSize === 0) cpSize = 0x10000;
      parts.push(base.subarray(cpOff, cpOff + cpSize)); total += cpSize;
    } else if (op > 0) {
      parts.push(delta.subarray(off, off + op)); total += op; off += op;
    } else throw new Error('delta op 0');
  }
  const out = Buffer.concat(parts);
  if (total !== tgtSize || out.length !== tgtSize) throw new Error('delta target size mismatch');
  return out;
}
function inflateAt(buf: Buffer, start: number, wantSize: number): { data: Buffer; next: number } {
  // inflateSync ignores trailing bytes: binary-search smallest prefix that inflates to wantSize
  let lo = 1; let hi = buf.length - start;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    try {
      const out = inflateSync(buf.subarray(start, start + mid));
      if (out.length === wantSize) { found = mid; hi = mid - 1; }
      else if (out.length < wantSize) lo = mid + 1;
      else hi = mid - 1;
    } catch { lo = mid + 1; }
  }
  if (found < 0) throw new Error('zlib inflate failed');
  return { data: inflateSync(buf.subarray(start, start + found)), next: start + found };
}
function parsePack(r: Repo, buf: Buffer): string[] {
  if (buf.length < 12 + 20) throw new Error('pack too short');
  if (buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a pack');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const count = buf.readUInt32BE(8);
  const trailer = buf.subarray(buf.length - 20).toString('hex');
  if (sha1hex(buf.subarray(0, buf.length - 20)) !== trailer) throw new Error('pack trailer mismatch');
  interface Raw { type: number; size: number; data: Buffer; ofsBase?: number; refBase?: string; start: number }
  const raws: Raw[] = [];
  let off = 12;
  const end = buf.length - 20;
  for (let i = 0; i < count; i++) {
    const start = off;
    const c0 = buf[off++] as number;
    let type = (c0 >> 4) & 0x7;
    let size = c0 & 0x0f;
    let shift = 4;
    let cont = (c0 & 0x80) !== 0;
    while (cont) {
      const b = buf[off++] as number;
      size |= (b & 0x7f) << shift; shift += 7;
      cont = (b & 0x80) !== 0;
    }
    let ofsBase: number | undefined;
    let refBase: string | undefined;
    if (type === 6) {
      let b = buf[off++] as number;
      let v = b & 0x7f;
      while (b & 0x80) { b = buf[off++] as number; v = ((v + 1) << 7) | (b & 0x7f); }
      ofsBase = start - v;
    } else if (type === 7) {
      refBase = buf.subarray(off, off + 20).toString('hex');
      off += 20;
    }
    const inf = inflateAt(buf, off, size);
    off = inf.next;
    raws.push({ type, size, data: inf.data, ofsBase, refBase, start });
    if (off > end) throw new Error('pack overrun');
  }
  const TYPE_MAP: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
  const byOffset = new Map<number, string>();
  const oids: string[] = [];
  for (const raw of raws) {
    let data = raw.data; let type: ObjType;
    if (raw.type === 6 || raw.type === 7) {
      let baseOid: string;
      if (raw.type === 6) {
        baseOid = byOffset.get(raw.ofsBase as number) as string;
        if (!baseOid) throw new Error('ofs delta base missing');
      } else {
        baseOid = raw.refBase as string;
      }
      const base = getObj(r, baseOid);
      if (!base) throw new Error('delta base not in store');
      data = deltaApply(base.data, raw.data);
      type = base.type;
    } else {
      type = TYPE_MAP[raw.type] as ObjType;
      if (!type) throw new Error('bad pack object type');
    }
    const oid = storeObj(r, type, data);
    byOffset.set(raw.start, oid);
    oids.push(oid);
  }
  return oids;
}
function buildPack(r: Repo, oids: string[]): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(oids.length, 8);
  parts.push(head);
  const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
  for (const oid of oids) {
    const o = getObj(r, oid);
    if (!o) continue;
    if (!o.deflated) o.deflated = deflateSync(o.data);
    const size = o.data.length;
    const hdr: number[] = [];
    let s = size;
    hdr.push(((TYPE_CODE[o.type] & 0x7) << 4) | (s & 0x0f));
    s >>= 4;
    while (s > 0) { hdr[hdr.length - 1] |= 0x80; hdr.push(s & 0x7f); s >>= 7; }
    parts.push(Buffer.from(hdr), o.deflated);
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, Buffer.from(sha1hex(body), 'hex')]);
}

// ---------- HTTP plumbing ----------
function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  reqCounter++;
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), 'x-github-request-id': String(reqCounter), ...extra });
  res.end(text);
}
function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string, extra: Record<string, string> = {}): void {
  reqCounter++;
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, 'x-github-request-id': String(reqCounter), ...extra });
  res.end(body);
}
function sendEmpty(res: ServerResponse, status: number): void {
  reqCounter++;
  res.writeHead(status, { 'x-github-request-id': String(reqCounter) });
  res.end();
}
function errJson(res: ServerResponse, status: number, message: string): void { sendJson(res, status, { message }); }
function decodeSeg(s: string): string { try { return decodeURIComponent(s); } catch { return s; } }
function splitPath(pathname: string): string[] {
  return pathname.split('/').filter((s) => s !== '').map(decodeSeg);
}
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function parseJsonBody(buf: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (buf.length === 0) return { ok: true, value: {} };
  try { return { ok: true, value: JSON.parse(buf.toString('utf8')) }; } catch { return { ok: false }; }
}
function asObj(v: unknown): Record<string, unknown> { return v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {}; }
function asStr(v: unknown, dflt = ''): string { return typeof v === 'string' ? v : dflt; }
function asBool(v: unknown, dflt = false): boolean { return typeof v === 'boolean' ? v : dflt; }

// ---------- repo / issue / PR JSON ----------
function repoJson(r: Repo): Record<string, unknown> {
  return { id: r.id, databaseId: r.id, name: r.name, private: r.priv, default_branch: 'main', description: r.description, full_name: `${r.owner}/${r.name}`, owner: { login: r.owner } };
}
function issueJson(i: IssueRec): Record<string, unknown> {
  return { id: i.id, number: i.number, title: i.title, body: i.body, state: i.state, labels: i.labels.map((l) => ({ name: l.name })) };
}
function prJson(p: PrRec): Record<string, unknown> {
  return { id: p.id, number: p.number, title: p.title, body: p.body, state: p.state, merged: p.merged, merged_at: p.merged_at, merge_commit_sha: p.merge_commit_sha, head: { ref: p.head.ref, sha: p.head.sha }, base: { ref: p.base.ref, sha: p.base.sha } };
}
function createRepo(name: string, priv: boolean, description: string): Repo {
  const r: Repo = {
    id: nextRepoId++, name, owner: VIEWER_LOGIN, priv, description,
    refs: new Map(), objects: new Map(), labels: new Map(),
    issues: [], prs: [], nextIssue: 1, nextPr: 1, order: repoOrder++,
  };
  repos.set(repoKey(VIEWER_LOGIN, name), r);
  return r;
}
// contents: commit one file on a branch (branch created from main tip if missing)
function commitFile(r: Repo, branch: string, path: string, content: Buffer, message: string): { commitSha: string; blobSha: string; isNew: boolean } {
  const refName = `refs/heads/${branch}`;
  let tip = r.refs.get(refName);
  let baseFiles = new Map<string, string>();
  let parents: string[] = [];
  if (tip) {
    parents = [tip];
    const tree = treeOfCommit(r, tip);
    const flat = new Map<string, { oid: string; mode: string }>();
    if (tree) flattenTree(r, tree, '', flat);
    for (const [p, v] of flat) baseFiles.set(p, v.oid);
  } else if (branch !== 'main') {
    const mainTip = r.refs.get('refs/heads/main');
    if (mainTip) {
      parents = [mainTip];
      const tree = treeOfCommit(r, mainTip);
      const flat = new Map<string, { oid: string; mode: string }>();
      if (tree) flattenTree(r, tree, '', flat);
      for (const [p, v] of flat) baseFiles.set(p, v.oid);
    }
  }
  const isNew = !baseFiles.has(path);
  const blobSha = storeObj(r, 'blob', content);
  baseFiles.set(path, blobSha);
  const treeOid = rebuildTree(r, baseFiles);
  const commitSha = makeCommit(r, treeOid, parents, message);
  r.refs.set(refName, commitSha);
  return { commitSha, blobSha, isNew };
}
function deleteFile(r: Repo, branch: string, path: string, message: string): { commitSha: string } | null {
  const refName = `refs/heads/${branch}`;
  const tip = r.refs.get(refName);
  if (!tip) return null;
  const tree = treeOfCommit(r, tip);
  const flat = new Map<string, { oid: string; mode: string }>();
  if (tree) flattenTree(r, tree, '', flat);
  if (!flat.has(path)) return null;
  const files = new Map<string, string>();
  for (const [p, v] of flat) if (p !== path) files.set(p, v.oid);
  const treeOid = rebuildTree(r, files);
  const commitSha = makeCommit(r, treeOid, [tip], message);
  r.refs.set(refName, commitSha);
  return { commitSha };
}
// merge engine (§8): returns {ok, sha?} or {ok:false, conflict:true}
function squashMerge(r: Repo, pr: PrRec): { ok: boolean; sha?: string } {
  const baseTipNow = r.refs.get(`refs/heads/${pr.base.ref}`) ?? '';
  const headTipNow = r.refs.get(`refs/heads/${pr.head.ref}`) ?? '';
  if (!baseTipNow || !headTipNow) return { ok: false };
  const baseTree = treeOfCommit(r, pr.base.sha);
  const headTree = treeOfCommit(r, headTipNow);
  const curTree = treeOfCommit(r, baseTipNow);
  const headDiff = treeDiff(r, baseTree, headTree);
  const baseDiff = treeDiff(r, baseTree, curTree);
  for (const [p, h] of headDiff) {
    const b = baseDiff.get(p);
    if (b && b.head !== h.head) return { ok: false };
  }
  const curFiles = new Map<string, string>();
  const flat = new Map<string, { oid: string; mode: string }>();
  if (curTree) flattenTree(r, curTree, '', flat);
  for (const [p, v] of flat) curFiles.set(p, v.oid);
  for (const [p, h] of headDiff) {
    if (h.head === undefined) curFiles.delete(p); else curFiles.set(p, h.head);
  }
  const treeOid = rebuildTree(r, curFiles);
  const sha = makeCommit(r, treeOid, [baseTipNow], `Merge pull request #${pr.number} from ${r.owner}/${pr.head.ref}`);
  r.refs.set(`refs/heads/${pr.base.ref}`, sha);
  pr.merged = true; pr.state = 'closed'; pr.merged_at = MERGED_AT; pr.merge_commit_sha = sha;
  return { ok: true, sha };
}
function prMergeable(r: Repo, pr: PrRec): string {
  if (pr.merged) return 'MERGEABLE';
  const baseTipNow = r.refs.get(`refs/heads/${pr.base.ref}`) ?? '';
  const headTipNow = r.refs.get(`refs/heads/${pr.head.ref}`) ?? '';
  if (!baseTipNow || !headTipNow) return 'UNKNOWN';
  const baseTree = treeOfCommit(r, pr.base.sha);
  const headTree = treeOfCommit(r, headTipNow);
  const curTree = treeOfCommit(r, baseTipNow);
  const headDiff = treeDiff(r, baseTree, headTree);
  const baseDiff = treeDiff(r, baseTree, curTree);
  for (const [p, h] of headDiff) {
    const b = baseDiff.get(p);
    if (b && b.head !== h.head) return 'CONFLICTING';
  }
  return 'MERGEABLE';
}
function prFiles(r: Repo, pr: PrRec): { filename: string; status: string; additions: number; deletions: number; changes: number }[] {
  const baseTree = treeOfCommit(r, pr.base.sha);
  const headTree = treeOfCommit(r, pr.head.sha);
  const diff = treeDiff(r, baseTree, headTree);
  const out: { filename: string; status: string; additions: number; deletions: number; changes: number }[] = [];
  const lineCount = (oid: string | undefined): number => {
    if (!oid) return 0;
    const o = getObj(r, oid);
    if (!o) return 0;
    const s = o.data.toString('utf8');
    if (s === '') return 0;
    return s.split('\n').length - (s.endsWith('\n') ? 1 : 0);
  };
  for (const p of [...diff.keys()].sort()) {
    const d = diff.get(p) as { base?: string; head?: string };
    if (d.base === undefined) {
      const a = lineCount(d.head);
      out.push({ filename: p, status: 'added', additions: a, deletions: 0, changes: a });
    } else if (d.head === undefined) {
      const dd = lineCount(d.base);
      out.push({ filename: p, status: 'removed', additions: 0, deletions: dd, changes: dd });
    } else {
      const a = lineCount(d.head); const dd = lineCount(d.base);
      out.push({ filename: p, status: 'modified', additions: Math.max(a, 1), deletions: dd, changes: Math.max(a, 1) + dd });
    }
  }
  return out;
}

// ---------- git smart HTTP ----------
function gitRepo(segs: string[]): Repo | undefined {
  // segs: [owner, repo.git, ...]
  if (segs.length < 2) return undefined;
  const owner = segs[0] as string;
  const repoSeg = segs[1] as string;
  if (!repoSeg.endsWith('.git')) return undefined;
  return getRepo(owner, repoSeg.slice(0, -4));
}
function allRefs(r: Repo): { ref: string; oid: string }[] {
  const out: { ref: string; oid: string }[] = [];
  for (const [ref, oid] of [...r.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) out.push({ ref, oid });
  return out;
}
function tagTarget(r: Repo, tagOid: string): string {
  const o = getObj(r, tagOid);
  if (!o || o.type !== 'tag') return '';
  return parseTag(o.data).object;
}
function infoRefs(req: IncomingMessage, res: ServerResponse, r: Repo, service: string, url: URL): void {
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  const mainTip = r.refs.get('refs/heads/main') ?? '';
  if (service === 'git-upload-pack' && isV2) {
    const caps = ['ls-refs=unborn', 'fetch=shallow', 'agent=makefun-forge/1.0'];
    const body = Buffer.concat([pkt('version 2\n'), ...caps.map((c) => pkt(`${c}\n`)), FLUSH]);
    sendRaw(res, 200, body, 'application/x-git-upload-pack-advertisement');
    return;
  }
  const isRecv = service === 'git-receive-pack';
  const caps = isRecv
    ? 'report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=makefun-forge/1.0'
    : 'side-band-64k shallow thin-pack ofs-delta multi_ack symref=HEAD:refs/heads/main agent=makefun-forge/1.0';
  const parts: Buffer[] = [];
  parts.push(pkt(`# service=${service}\n`), FLUSH);
  const refs = allRefs(r);
  if (refs.length === 0) {
    parts.push(pkt(`${ZERO} capabilities^{}\0${caps}\n`));
  } else {
    const headOid = mainTip || refs[0]?.oid || ZERO;
    parts.push(pkt(`${headOid} HEAD\0${caps}\n`));
    for (const { ref, oid } of refs) {
      parts.push(pkt(`${oid} ${ref}\n`));
      if (ref.startsWith('refs/tags/')) {
        const tgt = tagTarget(r, oid);
        if (tgt) parts.push(pkt(`${tgt} ${ref}^{}\n`));
      }
    }
  }
  sendRaw(res, 200, Buffer.concat(parts), isRecv ? 'application/x-git-receive-pack-advertisement' : 'application/x-git-upload-pack-advertisement');
}
function lsRefs(r: Repo, args: string[]): Buffer {
  const peel = args.includes('peel');
  const symrefs = args.includes('symrefs');
  const unborn = args.includes('unborn');
  const prefixes = args.filter((a) => a.startsWith('ref-prefix ')).map((a) => a.slice('ref-prefix '.length));
  const match = (ref: string): boolean => prefixes.length === 0 || prefixes.some((p) => ref.startsWith(p));
  const parts: Buffer[] = [];
  const mainTip = r.refs.get('refs/heads/main');
  if (mainTip === undefined && unborn && match('refs/heads/main')) {
    parts.push(pkt('unborn HEAD symref-target:refs/heads/main\n'));
  }
  if (mainTip !== undefined && symrefs && prefixes.length === 0) {
    parts.push(pkt(`${mainTip} HEAD symref-target:refs/heads/main\n`));
  }
  for (const { ref, oid } of allRefs(r)) {
    if (!match(ref)) continue;
    if (ref.startsWith('refs/tags/') && peel) {
      const tgt = tagTarget(r, oid);
      parts.push(pkt(tgt ? `${oid} ${ref} peeled:${tgt}\n` : `${oid} ${ref}\n`));
    } else {
      parts.push(pkt(`${oid} ${ref}\n`));
    }
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}
interface FetchReq { wants: string[]; haves: string[]; shallowHeld: string[]; deepen?: number }
function fetchObjects(r: Repo, fq: FetchReq): { packOids: string[]; boundaries: string[]; unshallow: string[] } {
  const cutoff = new Set(fq.shallowHeld);
  const haveSet = closure(r, fq.haves, undefined, cutoff);
  let wantSet: Set<string>;
  let boundaries: string[] = [];
  if (fq.deepen !== undefined) {
    wantSet = closure(r, fq.wants, fq.deepen);
    boundaries = boundaryCommits(r, fq.wants, fq.deepen);
  } else {
    wantSet = closure(r, fq.wants);
  }
  const packOids: string[] = [];
  for (const oid of wantSet) if (!haveSet.has(oid)) packOids.push(oid);
  // deterministic order: commits, then trees, then blobs/tags by oid
  const rank = (oid: string): number => { const o = getObj(r, oid); return o?.type === 'commit' ? 0 : o?.type === 'tree' ? 1 : o?.type === 'tag' ? 2 : 3; };
  packOids.sort((a, b) => rank(a) - rank(b) || (a < b ? -1 : 1));
  const unshallow = fq.shallowHeld.filter((s) => wantSet.has(s) && !boundaries.includes(s));
  return { packOids, boundaries, unshallow };
}
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let off = 0; off < pack.length; off += 65515) {
    const chunk = pack.subarray(off, Math.min(pack.length, off + 65515));
    parts.push(pkt(Buffer.concat([Buffer.from([1]), chunk])));
  }
  if (pack.length === 0) parts.push(pkt(Buffer.from([1])));
  parts.push(FLUSH);
  return Buffer.concat(parts);
}
function v2Fetch(r: Repo, fq: FetchReq): Buffer {
  const { packOids, boundaries, unshallow } = fetchObjects(r, fq);
  const ackLines: string[] = [];
  const haveKnown = fq.haves.filter((h) => getObj(r, h));
  const parts: Buffer[] = [];
  parts.push(pkt('acknowledgments\n'));
  if (fq.haves.length > 0 && haveKnown.length === fq.haves.length) {
    for (const h of haveKnown) parts.push(pkt(`ACK ${h}\n`));
    parts.push(pkt('ready\n'));
  } else {
    parts.push(pkt('NAK\n'));
  }
  parts.push(DELIM);
  if (boundaries.length > 0 || unshallow.length > 0) {
    parts.push(pkt('shallow-info\n'));
    for (const b of boundaries) parts.push(pkt(`shallow ${b}\n`));
    for (const u of unshallow) parts.push(pkt(`unshallow ${u}\n`));
    parts.push(DELIM);
  }
  const wanted: string[] = [];
  for (const { ref, oid } of allRefs(r)) if (fq.wants.includes(oid)) wanted.push(`${oid} ${ref}\n`);
  if (wanted.length > 0) {
    parts.push(pkt('wanted-refs\n'));
    for (const w of wanted) parts.push(pkt(w));
    parts.push(DELIM);
  }
  parts.push(pkt('packfile\n'));
  parts.push(sidebandPack(buildPack(r, packOids)));
  return Buffer.concat(parts);
}
function v0Fetch(r: Repo, fq: FetchReq): Buffer {
  const { packOids, boundaries, unshallow } = fetchObjects(r, fq);
  const parts: Buffer[] = [];
  const haveKnown = fq.haves.filter((h) => getObj(r, h));
  if (fq.haves.length > 0 && haveKnown.length === fq.haves.length) {
    for (const h of haveKnown) parts.push(pkt(`ACK ${h}\n`));
  } else {
    parts.push(pkt('NAK\n'));
  }
  for (const b of boundaries) parts.push(pkt(`shallow ${b}\n`));
  for (const u of unshallow) parts.push(pkt(`unshallow ${u}\n`));
  parts.push(sidebandPack(buildPack(r, packOids)));
  return Buffer.concat(parts);
}
function handleUploadPack(req: IncomingMessage, res: ServerResponse, r: Repo, body: Buffer): void {
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  let pkts: Pkt[];
  try { pkts = parsePkts(body); } catch { errJson(res, 400, 'Bad request'); return; }
  if (isV2) {
    const lines = pktLines(pkts);
    const delimIdx = pkts.findIndex((p) => p.kind === 'delim');
    const pre = delimIdx >= 0 ? lines.slice(0, delimIdx) : lines;
    const post = delimIdx >= 0 ? lines.slice(delimIdx) : [];
    // lines[] only counts data packets; recompute post args from packet order instead:
    const allData: string[] = [];
    let seenDelim = false;
    const args: string[] = [];
    for (const p of pkts) {
      if (p.kind === 'delim') { seenDelim = true; continue; }
      if (p.kind === 'flush') continue;
      if (p.kind === 'data') {
        if (!seenDelim) allData.push(p.payload.toString('utf8'));
        else args.push(p.payload.toString('utf8'));
      }
    }
    void pre; void post;
    const command = (allData[0] ?? '').trim().replace(/^command=/, '');
    if (command === 'ls-refs') {
      const a = args.map((s) => s.trim()).filter(Boolean);
      sendRaw(res, 200, lsRefs(r, a), 'application/x-git-upload-pack-result');
      return;
    }
    if (command === 'fetch') {
      const fq: FetchReq = { wants: [], haves: [], shallowHeld: [] };
      for (const a of args) {
        const s = a.trim();
        if (s.startsWith('want ')) fq.wants.push(s.slice(5).trim());
        else if (s.startsWith('have ')) fq.haves.push(s.slice(5).trim());
        else if (s.startsWith('shallow ')) fq.shallowHeld.push(s.slice(8).trim());
        else if (s.startsWith('deepen ')) fq.deepen = parseInt(s.slice(7).trim(), 10);
      }
      sendRaw(res, 200, v2Fetch(r, fq), 'application/x-git-upload-pack-result');
      return;
    }
    errJson(res, 400, 'Bad request');
    return;
  }
  // v0 fetch
  const lines = pktLines(pkts);
  const fq: FetchReq = { wants: [], haves: [], shallowHeld: [] };
  let seenFlush = false;
  for (const p of pkts) {
    if (p.kind === 'flush') { seenFlush = true; continue; }
    if (p.kind !== 'data') continue;
    const s = p.payload.toString('utf8').trim();
    if (s.startsWith('want ')) {
      const rest = s.slice(5);
      const nul = rest.indexOf('\0');
      fq.wants.push((nul >= 0 ? rest.slice(0, nul) : rest).trim());
    } else if (s.startsWith('shallow ')) fq.shallowHeld.push(s.slice(8).trim());
    else if (s.startsWith('deepen ')) fq.deepen = parseInt(s.slice(7).trim(), 10);
    else if (seenFlush && s.startsWith('have ')) fq.haves.push(s.slice(5).trim());
    else if (s.startsWith('have ')) fq.haves.push(s.slice(5).trim());
  }
  void lines;
  sendRaw(res, 200, v0Fetch(r, fq), 'application/x-git-upload-pack-result');
}
function handleReceivePack(req: IncomingMessage, res: ServerResponse, r: Repo, body: Buffer): void {
  // NOTE: do NOT parsePkts() the whole body — after the command flush comes a raw
  // binary pack, which is not pkt-line framed. Walk pkt-lines manually instead.
  interface Cmd { oldOid: string; newOid: string; ref: string }
  const cmds: Cmd[] = [];
  let packStart = -1;
  let off = 0;
  // walk raw bytes: pkt-lines until first flush, rest is the pack
  while (off + 4 <= body.length) {
    const head = body.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = parseInt(head, 16);
    if (len === 0) { off += 4; packStart = off; break; }
    if (len < 4 || off + len > body.length) break;
    const payload = body.subarray(off + 4, off + len).toString('utf8');
    const nul = payload.indexOf('\0');
    const line = (nul >= 0 ? payload.slice(0, nul) : payload).trim();
    const m = line.match(/^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/);
    if (m) cmds.push({ oldOid: m[1] as string, newOid: m[2] as string, ref: m[3] as string });
    off += len;
  }
  const packBytes = packStart >= 0 && packStart < body.length ? body.subarray(packStart) : Buffer.alloc(0);
  let unpackOk = true; let unpackMsg = 'ok';
  if (packBytes.length > 0) {
    try { parsePack(r, packBytes); } catch (e) { unpackOk = false; unpackMsg = e instanceof Error ? e.message : 'unpack failed'; }
  }
  const reportLines: string[] = [];
  reportLines.push(unpackOk ? 'unpack ok\n' : `unpack ${unpackMsg}\n`);
  for (const c of cmds) {
    if (!unpackOk) { reportLines.push(`ng ${c.ref} unpack failed\n`); continue; }
    const current = r.refs.get(c.ref);
    if (c.newOid === ZERO) {
      if (current !== undefined && c.oldOid === current) { r.refs.delete(c.ref); reportLines.push(`ok ${c.ref}\n`); }
      else reportLines.push(`ng ${c.ref} non-fast-forward\n`);
      continue;
    }
    if (current === undefined) {
      if (c.oldOid === ZERO && getObj(r, c.newOid)) { r.refs.set(c.ref, c.newOid); reportLines.push(`ok ${c.ref}\n`); }
      else reportLines.push(`ng ${c.ref} non-fast-forward\n`);
      continue;
    }
    if (c.oldOid === current && isDescendant(r, c.newOid, current)) {
      r.refs.set(c.ref, c.newOid);
      reportLines.push(`ok ${c.ref}\n`);
    } else {
      reportLines.push(`ng ${c.ref} non-fast-forward\n`);
    }
  }
  const inner: Buffer[] = [];
  for (const line of reportLines) inner.push(pkt(Buffer.concat([Buffer.from([1]), pkt(line)])));
  inner.push(pkt(Buffer.concat([Buffer.from([1]), Buffer.from('0000', 'ascii')])));
  inner.push(FLUSH);
  sendRaw(res, 200, Buffer.concat(inner), 'application/x-git-receive-pack-result');
}

// ---------- REST v3 ----------
function needRepo(res: ServerResponse, owner: string, name: string): Repo | null {
  const r = getRepo(owner, name);
  if (!r) { errJson(res, 404, 'Not Found'); return null; }
  return r;
}
function repoRoute(res: ServerResponse, owner: string, name: string): Repo | null {
  // owner must be the viewer; any other owner is 404, never 403
  if (owner !== VIEWER_LOGIN) { errJson(res, 404, 'Not Found'); return null; }
  return needRepo(res, owner, name);
}
async function handleRest(req: IncomingMessage, res: ServerResponse, segs: string[], url: URL, body: Buffer): Promise<void> {
  const method = req.method ?? 'GET';
  // root / meta (no auth)
  if (segs.length === 0 || (segs.length === 1 && segs[0] === '')) { /* unreachable */ }
  if (method === 'GET' && segs.length === 0) {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }
  if (method === 'GET' && segs.length === 1 && segs[0] === 'meta') {
    sendJson(res, 200, { installed_version: '1.0.0' });
    return;
  }
  if (!authed(req)) { errJson(res, 401, 'Bad credentials'); return; }
  if (method === 'GET' && segs.length === 1 && segs[0] === 'user') {
    sendJson(res, 200, { login: VIEWER_LOGIN, id: VIEWER_ID });
    return;
  }
  // /user/repos
  if (segs.length === 2 && segs[0] === 'user' && segs[1] === 'repos') {
    if (method === 'GET') {
      const perPage = Math.max(1, Math.min(100, parseInt(url.searchParams.get('per_page') ?? '30', 10) || 30));
      const page = Math.max(1, parseInt(url.searchParams.get('page') ?? '1', 10) || 1);
      const all = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.order - b.order);
      const slice = all.slice((page - 1) * perPage, page * perPage);
      const extra: Record<string, string> = {};
      if (page * perPage < all.length) {
        const host = req.headers.host ?? 'localhost';
        const nextUrl = `http://${host}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}`;
        extra.link = `<${nextUrl}>; rel="next"`;
      }
      sendJson(res, 200, slice.map(repoJson), extra);
      return;
    }
    if (method === 'POST') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
      const b = asObj(parsed.value);
      const name = asStr(b.name);
      if (!name || name.length > 100) { errJson(res, 422, 'Invalid repository name'); return; }
      if (getRepo(VIEWER_LOGIN, name)) { errJson(res, 422, 'Repository already exists'); return; }
      const r = createRepo(name, asBool(b.private, false), asStr(b.description, ''));
      sendJson(res, 201, repoJson(r));
      return;
    }
    errJson(res, 404, 'Not Found');
    return;
  }
  // /repos/{o}/{r}[...]
  if (segs.length >= 3 && segs[0] === 'repos') {
    const owner = segs[1] as string;
    const name = segs[2] as string;
    const rest = segs.slice(3);
    // repo object itself
    if (rest.length === 0) {
      if (method === 'GET') {
        const r = repoRoute(res, owner, name);
        if (r) sendJson(res, 200, repoJson(r));
        return;
      }
      if (method === 'PATCH') {
        const r = repoRoute(res, owner, name);
        if (!r) return;
        const parsed = parseJsonBody(body);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
        const b = asObj(parsed.value);
        if (typeof b.description === 'string') r.description = b.description;
        sendJson(res, 200, repoJson(r));
        return;
      }
      if (method === 'DELETE') {
        const r = repoRoute(res, owner, name);
        if (!r) return;
        repos.delete(repoKey(owner, name));
        sendEmpty(res, 204);
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    const r = repoRoute(res, owner, name);
    if (!r) return;
    // git/refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const parsed = parseJsonBody(body);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
        const b = asObj(parsed.value);
        const ref = asStr(b.ref);
        const sha = asStr(b.sha);
        if (!ref || !isOid(sha) || !getObj(r, sha)) { errJson(res, 422, 'Invalid ref or sha'); return; }
        if (r.refs.has(ref)) { errJson(res, 422, 'Reference already exists'); return; }
        r.refs.set(ref, sha);
        sendJson(res, 201, { ref, object: { sha } });
        return;
      }
      if (method === 'GET' && rest.length >= 4 && rest[2] === 'heads') {
        const branch = rest.slice(3).join('/');
        const sha = r.refs.get(`refs/heads/${branch}`);
        if (!sha) { errJson(res, 404, 'Not Found'); return; }
        sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha } });
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    // branches
    if (rest[0] === 'branches') {
      if (method === 'GET' && rest.length === 1) {
        const list = [...r.refs.entries()].filter(([k]) => k.startsWith('refs/heads/')).map(([k, v]) => ({ name: k.slice('refs/heads/'.length), commit: { sha: v } }));
        list.sort((a, b) => (a.name === 'main' ? -1 : b.name === 'main' ? 1 : a.name < b.name ? -1 : 1));
        sendJson(res, 200, list);
        return;
      }
      if (method === 'GET' && rest.length >= 2) {
        const branch = rest.slice(1).join('/');
        const sha = r.refs.get(`refs/heads/${branch}`);
        if (!sha) { errJson(res, 404, 'Not Found'); return; }
        sendJson(res, 200, { name: branch, commit: { sha } });
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    // commits
    if (rest[0] === 'commits' && method === 'GET' && rest.length === 1) {
      const ref = url.searchParams.get('sha') ?? undefined;
      const tip = resolveRef(r, ref);
      const out: { sha: string; commit: { message: string } }[] = [];
      if (tip) {
        const seen = new Set<string>();
        const stack = [tip];
        while (stack.length) {
          const oid = stack.pop() as string;
          if (seen.has(oid)) continue;
          seen.add(oid);
          const o = getObj(r, oid);
          if (!o || o.type !== 'commit') continue;
          const c = parseCommit(o.data);
          out.push({ sha: oid, commit: { message: c.message } });
          for (const p of c.parents) stack.push(p);
        }
      }
      sendJson(res, 200, out);
      return;
    }
    // contents
    if (rest[0] === 'contents') {
      const path = rest.slice(1).join('/');
      if (method === 'PUT') {
        const parsed = parseJsonBody(body);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
        const b = asObj(parsed.value);
        const contentB64 = asStr(b.content);
        if (!contentB64) { errJson(res, 400, 'Missing content'); return; }
        const branch = asStr(b.branch, 'main');
        const message = asStr(b.message, `Update ${path}`);
        const content = Buffer.from(contentB64, 'base64');
        const sha = asStr(b.sha, '');
        if (sha) {
          const tip = r.refs.get(`refs/heads/${branch}`);
          let cur = '';
          if (tip) {
            const tree = treeOfCommit(r, tip);
            const flat = new Map<string, { oid: string; mode: string }>();
            if (tree) flattenTree(r, tree, '', flat);
            cur = flat.get(path)?.oid ?? '';
          }
          if (!cur || cur.toLowerCase() !== sha.toLowerCase()) { errJson(res, 409, 'Conflict'); return; }
        }
        const { commitSha, blobSha, isNew } = commitFile(r, branch, path, content, message);
        sendJson(res, isNew ? 201 : 200, { content: { sha: blobSha, encoding: 'base64' }, commit: { sha: commitSha } });
        return;
      }
      if (method === 'GET') {
        const ref = url.searchParams.get('ref') ?? undefined;
        const tip = resolveRef(r, ref);
        if (!tip) { errJson(res, 404, 'Not Found'); return; }
        const tree = treeOfCommit(r, tip);
        const flat = new Map<string, { oid: string; mode: string }>();
        if (tree) flattenTree(r, tree, '', flat);
        if (path === '') {
          // root directory listing
          const children = new Map<string, { type: string; name: string; path: string; sha: string }>();
          for (const p of flat.keys()) {
            const first = p.split('/')[0] as string;
            if (p.includes('/')) {
              if (!children.has(first)) {
                const sub = new Map<string, string>();
                for (const [pp, v] of flat) if (pp.startsWith(`${first}/`)) sub.set(pp.slice(first.length + 1), v.oid);
                children.set(first, { type: 'dir', name: first, path: first, sha: rebuildTree(r, sub) });
              }
            } else {
              children.set(first, { type: 'file', name: first, path: first, sha: flat.get(p)?.oid ?? '' });
            }
          }
          sendJson(res, 200, [...children.values()].sort((a, b) => (a.name < b.name ? -1 : 1)));
          return;
        }
        const file = flat.get(path);
        if (file) {
          const o = getObj(r, file.oid);
          const data = o ? o.data : Buffer.alloc(0);
          sendJson(res, 200, { type: 'file', encoding: 'base64', content: b64encBuf(data), sha: file.oid, size: data.length, name: path.split('/').pop() ?? path, path });
          return;
        }
        // directory?
        const prefix = `${path}/`;
        const children = new Map<string, { type: string; name: string; path: string; sha: string }>();
        for (const p of flat.keys()) {
          if (!p.startsWith(prefix)) continue;
          const restPath = p.slice(prefix.length);
          const first = restPath.split('/')[0] as string;
          if (restPath.includes('/')) {
            if (!children.has(first)) {
              const sub = new Map<string, string>();
              for (const [pp, v] of flat) if (pp.startsWith(`${prefix}${first}/`)) sub.set(pp.slice(prefix.length + first.length + 1), v.oid);
              children.set(first, { type: 'dir', name: first, path: `${path}/${first}`, sha: rebuildTree(r, sub) });
            }
          } else {
            children.set(first, { type: 'file', name: first, path: p, sha: flat.get(p)?.oid ?? '' });
          }
        }
        if (children.size > 0) {
          sendJson(res, 200, [...children.values()].sort((a, b) => (a.name < b.name ? -1 : 1)));
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      if (method === 'DELETE') {
        const parsed = parseJsonBody(body);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
        const b = asObj(parsed.value);
        const message = asStr(b.message, `Delete ${path}`);
        const sha = asStr(b.sha, '');
        const branch = asStr(b.branch, 'main');
        const tip = r.refs.get(`refs/heads/${branch}`);
        if (!tip) { errJson(res, 404, 'Not Found'); return; }
        const tree = treeOfCommit(r, tip);
        const flat = new Map<string, { oid: string; mode: string }>();
        if (tree) flattenTree(r, tree, '', flat);
        const cur = flat.get(path)?.oid ?? '';
        if (!cur) { errJson(res, 404, 'Not Found'); return; }
        if (sha && cur.toLowerCase() !== sha.toLowerCase()) { errJson(res, 409, 'Conflict'); return; }
        const del = deleteFile(r, branch, path, message);
        if (!del) { errJson(res, 404, 'Not Found'); return; }
        sendJson(res, 200, { commit: { sha: del.commitSha } });
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    // labels
    if (rest[0] === 'labels' && method === 'POST' && rest.length === 1) {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
      const b = asObj(parsed.value);
      const name = asStr(b.name);
      const color = asStr(b.color, 'ededed');
      if (!name) { errJson(res, 422, 'Invalid label'); return; }
      r.labels.set(name, { name, color });
      sendJson(res, 201, { name, color });
      return;
    }
    // issues
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const parsed = parseJsonBody(body);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
          const b = asObj(parsed.value);
          const title = asStr(b.title);
          if (!title) { errJson(res, 422, 'Title is required'); return; }
          const labels = Array.isArray(b.labels) ? (b.labels as unknown[]).map((x) => String(x)) : [];
          for (const l of labels) if (!r.labels.has(l)) { errJson(res, 422, `Label ${l} does not exist`); return; }
          const issue: IssueRec = { id: nextEntityId++, number: r.nextIssue++, title, body: asStr(b.body, ''), state: 'open', labels: labels.map((name) => ({ name })), comments: [] };
          r.issues.push(issue);
          sendJson(res, 201, issueJson(issue));
          return;
        }
        if (method === 'GET') {
          const state = url.searchParams.get('state') ?? 'open';
          const sort = url.searchParams.get('sort') ?? 'created';
          const dir = url.searchParams.get('direction') ?? 'desc';
          let list = r.issues.filter((i) => state === 'all' || i.state === state);
          if (sort === 'created') list = [...list].sort((a, b) => (dir === 'asc' ? a.number - b.number : b.number - a.number));
          sendJson(res, 200, list.map(issueJson));
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      const num = parseInt(rest[1] as string, 10);
      const issue = r.issues.find((i) => i.number === num);
      if (rest.length === 2) {
        if (!issue) { errJson(res, 404, 'Not Found'); return; }
        if (method === 'GET') { sendJson(res, 200, issueJson(issue)); return; }
        if (method === 'PATCH') {
          const parsed = parseJsonBody(body);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
          const b = asObj(parsed.value);
          if (b.state === 'open' || b.state === 'closed') issue.state = b.state;
          if (typeof b.title === 'string') issue.title = b.title;
          if (typeof b.body === 'string') issue.body = b.body;
          sendJson(res, 200, issueJson(issue));
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        if (!issue) { errJson(res, 404, 'Not Found'); return; }
        if (method === 'POST') {
          const parsed = parseJsonBody(body);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
          const b = asObj(parsed.value);
          const c: CommentRec = { id: nextEntityId++, body: asStr(b.body, '') };
          issue.comments.push(c);
          sendJson(res, 201, { id: c.id, body: c.body });
          return;
        }
        if (method === 'GET') {
          sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, body: c.body })));
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    // pulls
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const parsed = parseJsonBody(body);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
          const b = asObj(parsed.value);
          const head = asStr(b.head);
          const base = asStr(b.base);
          const headSha = r.refs.get(`refs/heads/${head}`);
          const baseSha = r.refs.get(`refs/heads/${base}`);
          if (!headSha || !baseSha) { errJson(res, 404, 'Not Found'); return; }
          const pr: PrRec = {
            id: nextEntityId++, number: r.nextPr++, title: asStr(b.title), body: asStr(b.body, ''),
            state: 'open', merged: false, merged_at: null, merge_commit_sha: null,
            head: { ref: head, sha: headSha }, base: { ref: base, sha: baseSha }, comments: [],
          };
          r.prs.push(pr);
          sendJson(res, 201, prJson(pr));
          return;
        }
        if (method === 'GET') {
          const state = url.searchParams.get('state');
          const list = r.prs.filter((p) => state === 'all' ? true : state === 'closed' ? p.state === 'closed' : state === 'open' ? p.state === 'open' : p.state === 'open');
          sendJson(res, 200, list.map(prJson));
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      const num = parseInt(rest[1] as string, 10);
      const pr = r.prs.find((p) => p.number === num);
      if (rest.length === 2) {
        if (!pr) { errJson(res, 404, 'Not Found'); return; }
        if (method === 'GET') { sendJson(res, 200, prJson(pr)); return; }
        errJson(res, 404, 'Not Found');
        return;
      }
      if (rest.length === 3 && rest[2] === 'files') {
        if (!pr) { errJson(res, 404, 'Not Found'); return; }
        if (method === 'GET') { sendJson(res, 200, prFiles(r, pr)); return; }
        errJson(res, 404, 'Not Found');
        return;
      }
      if (rest.length === 3 && rest[2] === 'merge') {
        if (!pr) { errJson(res, 404, 'Not Found'); return; }
        if (method === 'PUT') {
          if (pr.merged) { sendJson(res, 200, { merged: true, sha: pr.merge_commit_sha ?? '', message: `Merge pull request #${pr.number}` }); return; }
          const m = squashMerge(r, pr);
          if (!m.ok) { errJson(res, 405, 'Merge conflict'); return; }
          sendJson(res, 200, { merged: true, sha: m.sha ?? '', message: `Merge pull request #${pr.number} from ${r.owner}/${pr.head.ref}` });
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    errJson(res, 404, 'Not Found');
    return;
  }
  errJson(res, 404, 'Not Found');
}

// ---------- GraphQL ----------
// Minimal document parser: fields, aliases, args (vars/literals/enums/objects/lists),
// inline fragments, __type. No named fragments are sent by the suite.
interface GqlArg { [k: string]: unknown }
interface Sel { alias: string; name: string; args: GqlArg; children: Sel[]; fragType?: string }
function tokenizeGql(src: string): string[] {
  const toks: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (c === ' ' || c === '\n' || c === '\t' || c === '\r' || c === ',') { i++; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '.' && src.slice(i, i + 3) === '...') { toks.push('...'); i += 3; continue; }
    if ('{}():![]=@$'.includes(c)) { toks.push(c); i++; continue; }
    if (c === '"') {
      let j = i + 1; let s = '';
      while (j < src.length && src[j] !== '"') { if (src[j] === '\\' && j + 1 < src.length) { s += src[j + 1]; j += 2; } else { s += src[j]; j++; } }
      toks.push(JSON.stringify(s)); i = j + 1; continue;
    }
    if (/[A-Za-z_0-9-]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z_0-9-]/.test(src[j] as string)) j++;
      toks.push(src.slice(i, j)); i = j; continue;
    }
    i++;
  }
  return toks;
}
class GqlParser {
  toks: string[]; pos = 0;
  constructor(src: string) { this.toks = tokenizeGql(src); }
  peek(): string { return this.toks[this.pos] ?? ''; }
  next(): string { return this.toks[this.pos++] ?? ''; }
  expect(t: string): void { if (this.peek() === t) this.pos++; }
  parseValue(vars: Record<string, unknown>): unknown {
    const t = this.next();
    if (t === '$') return vars[this.next()] ?? null;
    if (t === '[') {
      const arr: unknown[] = [];
      while (this.peek() !== ']' && this.pos < this.toks.length) arr.push(this.parseValue(vars));
      this.expect(']');
      return arr;
    }
    if (t === '{') {
      const obj: Record<string, unknown> = {};
      while (this.peek() !== '}' && this.pos < this.toks.length) {
        const k = this.next();
        this.expect(':');
        obj[k] = this.parseValue(vars);
      }
      this.expect('}');
      return obj;
    }
    if (t.startsWith('"')) { try { return JSON.parse(t); } catch { return t; } }
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (t === 'null') return null;
    const n = Number(t);
    if (t !== '' && !Number.isNaN(n) && /^-?[0-9]/.test(t)) return n;
    return t; // enum as string
  }
  parseArgs(vars: Record<string, unknown>): GqlArg {
    const args: GqlArg = {};
    this.expect('(');
    while (this.peek() !== ')' && this.pos < this.toks.length) {
      const k = this.next();
      this.expect(':');
      args[k] = this.parseValue(vars);
    }
    this.expect(')');
    return args;
  }
  parseSelectionSet(vars: Record<string, unknown>): Sel[] {
    const sels: Sel[] = [];
    this.expect('{');
    while (this.peek() !== '}' && this.pos < this.toks.length) {
      if (this.peek() === '...') {
        this.next();
        let fragType: string | undefined;
        if (this.peek() === 'on') { this.next(); fragType = this.next(); }
        const children = this.parseSelectionSet(vars);
        for (const c of children) sels.push({ ...c, fragType });
        continue;
      }
      let name = this.next();
      let alias = name;
      if (this.peek() === ':') { this.next(); alias = name; name = this.next(); }
      let args: GqlArg = {};
      if (this.peek() === '(') args = this.parseArgs(vars);
      let children: Sel[] = [];
      if (this.peek() === '{') children = this.parseSelectionSet(vars);
      sels.push({ alias, name, args, children });
    }
    this.expect('}');
    return sels;
  }
  parseOperation(vars: Record<string, unknown>): { type: string; sels: Sel[] } {
    let type = 'query';
    let t = this.peek();
    if (t === 'query' || t === 'mutation') { type = this.next(); t = this.peek(); }
    if (t !== '{' && t !== '(') this.next(); // operation name
    if (this.peek() === '(') {
      // variable definitions: skip, values come from vars
      let depth = 0;
      while (this.pos < this.toks.length) {
        const tok = this.next();
        if (tok === '(') depth++;
        else if (tok === ')') { depth--; if (depth === 0) break; }
      }
    }
    const sels = this.parseSelectionSet(vars);
    return { type, sels };
  }
}
const TYPE_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests'],
  Issue: ['id', 'number', 'title', 'state', 'body'],
  PullRequest: ['id', 'number', 'title', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files'],
  User: ['login', 'id'],
  Ref: ['name'],
  IssueConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestFileConnection: ['nodes', 'pageInfo'],
  PageInfo: ['hasNextPage', 'endCursor'],
  IssueEdge: ['node', 'cursor'],
  PullRequestEdge: ['node', 'cursor'],
  PullRequestFile: ['path'],
  CreateIssuePayload: ['issue'],
  CloseIssuePayload: ['issue'],
  CreatePullRequestPayload: ['pullRequest'],
  MergePullRequestPayload: ['pullRequest'],
  AddCommentPayload: ['commentEdge'],
  CommentEdge: ['node'],
  IssueComment: ['id', 'body'],
  __Type: ['fields', 'enumValues', 'name'],
  __Field: ['name'],
  __EnumValue: ['name'],
};
const ISSUE_TYPE_FIELDS = ['id', 'number', 'title', 'state', 'body'];
const PR_TYPE_FIELDS = ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'];
const REPO_TYPE_FIELDS = ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'];
interface Ctx { kind: string; repo?: Repo; issue?: IssueRec; pr?: PrRec; comment?: CommentRec; typeName?: string; list?: unknown[]; pageInfo?: { hasNextPage: boolean; endCursor: string | null } }
function gqlError(msg: string): { message: string } { return { message: msg }; }
function resolveField(ctx: Ctx, sel: Sel, errors: { message: string }[]): unknown {
  const known = TYPE_FIELDS[ctx.kind] ?? [];
  if (!known.includes(sel.name)) {
    errors.push(gqlError(`Cannot query field "${sel.name}" on type "${ctx.kind}".`));
    return null;
  }
  if (sel.fragType) {
    const fragMap: Record<string, string> = { Repository: 'Repository', Issue: 'Issue', PullRequest: 'PullRequest' };
    if (fragMap[sel.fragType] && fragMap[sel.fragType] !== ctx.kind && ctx.kind !== 'Query') {
      // inline fragment on a different type: field does not apply
      if (ctx.kind === 'Node') {
        // node ctx kind is the resolved type; handled by caller
      } else return null;
    }
  }
  switch (ctx.kind) {
    case 'Query': return resolveQuery(ctx, sel, errors);
    case 'Mutation': return resolveMutation(ctx, sel, errors);
    case 'Repository': return resolveRepoField(ctx, sel, errors);
    case 'Issue': return resolveIssueField(ctx, sel, errors);
    case 'PullRequest': return resolvePrField(ctx, sel, errors);
    case 'User': return sel.name === 'login' ? VIEWER_LOGIN : VIEWER_ID;
    case 'Ref': return 'main';
    case 'IssueConnection': case 'PullRequestConnection': case 'PullRequestFileConnection': {
      if (sel.name === 'nodes') return (ctx.list ?? []).map((item) => resolveNodeItem(ctx, item, sel.children, errors));
      if (sel.name === 'pageInfo') return resolvePageInfo(ctx, sel.children);
      if (sel.name === 'totalCount') return (ctx.list ?? []).length;
      return null;
    }
    case 'PageInfo': return sel.name === 'hasNextPage' ? (ctx.pageInfo?.hasNextPage ?? false) : (ctx.pageInfo?.endCursor ?? null);
    case 'CreateIssuePayload': case 'CloseIssuePayload': {
      if (!ctx.issue || !ctx.repo) return null;
      return resolveChildren({ kind: 'Issue', repo: ctx.repo, issue: ctx.issue }, sel.children, errors);
    }
    case 'CreatePullRequestPayload': case 'MergePullRequestPayload': {
      if (!ctx.pr || !ctx.repo) return null;
      return resolveChildren({ kind: 'PullRequest', repo: ctx.repo, pr: ctx.pr }, sel.children, errors);
    }
    case 'AddCommentPayload': {
      if (sel.name === 'commentEdge') {
        if (!ctx.comment) return null;
        return resolveChildren({ kind: 'CommentEdge', repo: ctx.repo, comment: ctx.comment }, sel.children, errors);
      }
      return null;
    }
    case 'CommentEdge': {
      if (sel.name === 'node' && ctx.comment && ctx.repo) {
        return resolveChildren({ kind: 'IssueComment', repo: ctx.repo, comment: ctx.comment }, sel.children, errors);
      }
      return null;
    }
    case 'IssueComment': {
      if (sel.name === 'id') return ctx.comment ? commentGid(ctx.repo as Repo, ctx.comment.id) : null;
      if (sel.name === 'body') return ctx.comment?.body ?? null;
      return null;
    }
    case '__Type': {
      if (sel.name === 'fields') {
        const names = ctx.typeName === 'Issue' ? ISSUE_TYPE_FIELDS : ctx.typeName === 'PullRequest' ? PR_TYPE_FIELDS : ctx.typeName === 'Repository' ? REPO_TYPE_FIELDS : [];
        return names.map((n) => ({ name: n }));
      }
      if (sel.name === 'enumValues') {
        if (ctx.typeName === 'SearchType') return ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'].map((n) => ({ name: n }));
        return [];
      }
      if (sel.name === 'name') return ctx.typeName ?? null;
      return null;
    }
    default: return null;
  }
}
function resolveChildren(ctx: Ctx, sels: Sel[], errors: { message: string }[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const s of sels) out[s.alias] = resolveField(ctx, s, errors);
  return out;
}
function resolveNodeItem(connCtx: Ctx, item: unknown, children: Sel[], errors: { message: string }[]): unknown {
  const repo = connCtx.repo as Repo;
  if (connCtx.kind === 'IssueConnection') {
    const issue = item as IssueRec;
    return resolveChildren({ kind: 'Issue', repo, issue }, children, errors);
  }
  if (connCtx.kind === 'PullRequestConnection') {
    const pr = item as PrRec;
    return resolveChildren({ kind: 'PullRequest', repo, pr }, children, errors);
  }
  // file connection: item is {path}
  const out: Record<string, unknown> = {};
  for (const s of children) out[s.alias] = s.name === 'path' ? (item as { path: string }).path : null;
  return out;
}
function resolvePageInfo(ctx: Ctx, children: Sel[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const s of children) {
    if (s.name === 'hasNextPage') out[s.alias] = ctx.pageInfo?.hasNextPage ?? false;
    if (s.name === 'endCursor') out[s.alias] = ctx.pageInfo?.endCursor ?? null;
  }
  return out;
}
function findRepoByGid(id: string): Repo | undefined {
  const dec = b64d(id);
  const m = dec.match(/^Repository:(\d+)$/);
  if (!m) return undefined;
  const db = parseInt(m[1] as string, 10);
  for (const r of repos.values()) if (r.id === db) return r;
  return undefined;
}
function decodeGid(id: string): { kind: string; repoId: number; num: number } | null {
  const dec = b64d(id);
  const m = dec.match(/^(Issue|PullRequest|IssueComment):(\d+):(\d+)$/);
  if (!m) return null;
  return { kind: m[1] as string, repoId: parseInt(m[2] as string, 10), num: parseInt(m[3] as string, 10) };
}
function resolveQuery(ctx: Ctx, sel: Sel, errors: { message: string }[]): unknown {
  if (sel.name === 'viewer') return resolveChildren({ kind: 'User' }, sel.children, errors);
  if (sel.name === '__type') {
    const name = asStr(sel.args.name);
    return resolveChildren({ kind: '__Type', typeName: name }, sel.children, errors);
  }
  if (sel.name === '__schema') {
    return resolveChildren({ kind: '__Type', typeName: 'Query' }, sel.children, errors);
  }
  if (sel.name === 'repository') {
    const owner = asStr(sel.args.owner);
    const name = asStr(sel.args.name);
    const r = owner === VIEWER_LOGIN ? getRepo(owner, name) : undefined;
    if (!r) return null;
    return resolveChildren({ kind: 'Repository', repo: r }, sel.children, errors);
  }
  if (sel.name === 'node') {
    const id = asStr(sel.args.id);
    const dec = b64d(id);
    const rm = dec.match(/^Repository:(\d+)$/);
    if (rm) {
      const r = findRepoByGid(id);
      if (!r) return null;
      return resolveChildren({ kind: 'Repository', repo: r }, sel.children, errors);
    }
    const g = decodeGid(id);
    if (g) {
      let r: Repo | undefined;
      for (const x of repos.values()) if (x.id === g.repoId) r = x;
      if (!r) return null;
      if (g.kind === 'Issue') {
        const issue = r.issues.find((i) => i.number === g.num);
        if (!issue) return null;
        return resolveChildren({ kind: 'Issue', repo: r, issue }, sel.children, errors);
      }
      if (g.kind === 'PullRequest') {
        const pr = r.prs.find((p) => p.number === g.num);
        if (!pr) return null;
        return resolveChildren({ kind: 'PullRequest', repo: r, pr }, sel.children, errors);
      }
    }
    return null;
  }
  return null;
}
function resolveRepoField(ctx: Ctx, sel: Sel, errors: { message: string }[]): unknown {
  const r = ctx.repo as Repo;
  switch (sel.name) {
    case 'id': return repoGid(r);
    case 'databaseId': return r.id;
    case 'name': return r.name;
    case 'nameWithOwner': return `${r.owner}/${r.name}`;
    case 'owner': return resolveChildren({ kind: 'User' }, sel.children, errors);
    case 'defaultBranchRef': return resolveChildren({ kind: 'Ref' }, sel.children, errors);
    case 'viewerPermission': return 'ADMIN';
    case 'hasIssuesEnabled': return true;
    case 'issue': {
      const n = sel.args.number as number;
      const issue = r.issues.find((i) => i.number === n);
      if (!issue) return null;
      return resolveChildren({ kind: 'Issue', repo: r, issue }, sel.children, errors);
    }
    case 'issues': {
      let list = [...r.issues];
      const states = sel.args.states as unknown;
      if (Array.isArray(states)) {
        const want = new Set(states.map((s) => String(s).toLowerCase()));
        list = list.filter((i) => want.has(i.state));
      }
      const orderBy = asObj(sel.args.orderBy);
      const field = asStr(orderBy.field, 'CREATED_AT');
      const dir = asStr(orderBy.direction, 'ASC');
      if (field === 'CREATED_AT') list.sort((a, b) => (dir === 'DESC' ? b.number - a.number : a.number - b.number));
      const first = typeof sel.args.first === 'number' ? sel.args.first as number : list.length;
      const after = sel.args.after as string | null | undefined;
      let start = 0;
      if (after) {
        const dec = b64d(after);
        const m = dec.match(/^cursor:(\d+)$/);
        if (m) {
          const idx = list.findIndex((i) => i.number === parseInt(m[1] as string, 10));
          if (idx >= 0) start = idx + 1;
        }
      }
      const page = list.slice(start, start + first);
      const hasNext = start + page.length < list.length;
      const endCursor = page.length > 0 ? b64e(`cursor:${(page[page.length - 1] as IssueRec).number}`) : null;
      const conn: Ctx = { kind: 'IssueConnection', repo: r, list: page, pageInfo: { hasNextPage: hasNext, endCursor } };
      return resolveChildren(conn, sel.children, errors);
    }
    case 'pullRequest': {
      const n = sel.args.number as number;
      const pr = r.prs.find((p) => p.number === n);
      if (!pr) return null;
      return resolveChildren({ kind: 'PullRequest', repo: r, pr }, sel.children, errors);
    }
    case 'pullRequests': {
      const first = typeof sel.args.first === 'number' ? sel.args.first as number : r.prs.length;
      const page = r.prs.slice(0, first);
      const conn: Ctx = { kind: 'PullRequestConnection', repo: r, list: page, pageInfo: { hasNextPage: r.prs.length > first, endCursor: null } };
      return resolveChildren(conn, sel.children, errors);
    }
    default: return null;
  }
}
function resolveIssueField(ctx: Ctx, sel: Sel, errors: { message: string }[]): unknown {
  const i = ctx.issue as IssueRec;
  const r = ctx.repo as Repo;
  switch (sel.name) {
    case 'id': return issueGid(r, i.number);
    case 'number': return i.number;
    case 'title': return i.title;
    case 'state': return i.state === 'open' ? 'OPEN' : 'CLOSED';
    case 'body': return i.body;
    default: return null;
  }
}
function resolvePrField(ctx: Ctx, sel: Sel, errors: { message: string }[]): unknown {
  const p = ctx.pr as PrRec;
  const r = ctx.repo as Repo;
  switch (sel.name) {
    case 'id': return prGid(r, p.number);
    case 'number': return p.number;
    case 'title': return p.title;
    case 'state': return p.merged ? 'MERGED' : p.state === 'open' ? 'OPEN' : 'CLOSED';
    case 'merged': return p.merged;
    case 'mergeable': return prMergeable(r, p);
    case 'headRefName': return p.head.ref;
    case 'baseRefName': return p.base.ref;
    case 'files': {
      const first = typeof sel.args.first === 'number' ? sel.args.first as number : 10;
      const files = prFiles(r, p).slice(0, first).map((f) => ({ path: f.filename }));
      const conn: Ctx = { kind: 'PullRequestFileConnection', repo: r, list: files, pageInfo: { hasNextPage: false, endCursor: null } };
      return resolveChildren(conn, sel.children, errors);
    }
    default: return null;
  }
}
function resolveMutation(ctx: Ctx, sel: Sel, errors: { message: string }[]): unknown {
  const input = asObj(sel.args.input);
  if (sel.name === 'createIssue') {
    const r = findRepoByGid(asStr(input.repositoryId));
    if (!r) return resolveChildren({ kind: 'CreateIssuePayload' }, sel.children, errors);
    const issue: IssueRec = { id: nextEntityId++, number: r.nextIssue++, title: asStr(input.title), body: asStr(input.body, ''), state: 'open', labels: [], comments: [] };
    r.issues.push(issue);
    return resolveChildren({ kind: 'CreateIssuePayload', repo: r, issue }, sel.children, errors);
  }
  if (sel.name === 'closeIssue') {
    const g = decodeGid(asStr(input.issueId));
    let issue: IssueRec | undefined; let r: Repo | undefined;
    if (g) for (const x of repos.values()) if (x.id === g.repoId) { r = x; issue = x.issues.find((i) => i.number === g.num); }
    if (issue) issue.state = 'closed';
    if (!r || !issue) return resolveChildren({ kind: 'CloseIssuePayload' }, sel.children, errors);
    return resolveChildren({ kind: 'CloseIssuePayload', repo: r, issue }, sel.children, errors);
  }
  if (sel.name === 'createPullRequest') {
    const r = findRepoByGid(asStr(input.repositoryId));
    if (!r) return resolveChildren({ kind: 'CreatePullRequestPayload' }, sel.children, errors);
    const head = asStr(input.headRefName);
    const base = asStr(input.baseRefName);
    const headSha = r.refs.get(`refs/heads/${head}`) ?? '';
    const baseSha = r.refs.get(`refs/heads/${base}`) ?? '';
    const pr: PrRec = {
      id: nextEntityId++, number: r.nextPr++, title: asStr(input.title), body: asStr(input.body, ''),
      state: 'open', merged: false, merged_at: null, merge_commit_sha: null,
      head: { ref: head, sha: headSha }, base: { ref: base, sha: baseSha }, comments: [],
    };
    r.prs.push(pr);
    return resolveChildren({ kind: 'CreatePullRequestPayload', repo: r, pr }, sel.children, errors);
  }
  if (sel.name === 'mergePullRequest') {
    const g = decodeGid(asStr(input.pullRequestId));
    let pr: PrRec | undefined; let r: Repo | undefined;
    if (g) for (const x of repos.values()) if (x.id === g.repoId) { r = x; pr = x.prs.find((p) => p.number === g.num); }
    if (pr && r) {
      const m = squashMerge(r, pr);
      void m;
    }
    if (!r || !pr) return resolveChildren({ kind: 'MergePullRequestPayload' }, sel.children, errors);
    return resolveChildren({ kind: 'MergePullRequestPayload', repo: r, pr }, sel.children, errors);
  }
  if (sel.name === 'addComment') {
    const g = decodeGid(asStr(input.subjectId));
    let r: Repo | undefined; let issue: IssueRec | undefined; let pr: PrRec | undefined;
    if (g) for (const x of repos.values()) if (x.id === g.repoId) {
      r = x;
      if (g.kind === 'Issue') issue = x.issues.find((i) => i.number === g.num);
      if (g.kind === 'PullRequest') pr = x.prs.find((p) => p.number === g.num);
    }
    const c: CommentRec = { id: nextEntityId++, body: asStr(input.body, '') };
    if (issue) issue.comments.push(c);
    else if (pr) pr.comments.push(c);
    if (!r) return resolveChildren({ kind: 'AddCommentPayload' }, sel.children, errors);
    return resolveChildren({ kind: 'AddCommentPayload', repo: r, comment: c }, sel.children, errors);
  }
  return null;
}
function runGqlOp(query: string, vars: Record<string, unknown>): { data: Record<string, unknown>; errors?: { message: string }[] } {
  const errors: { message: string }[] = [];
  let op: { type: string; sels: Sel[] };
  try {
    const parser = new GqlParser(query);
    op = parser.parseOperation(vars);
  } catch {
    return { data: {}, errors: [gqlError('Syntax Error: could not parse query')] };
  }
  const rootCtx: Ctx = { kind: op.type === 'mutation' ? 'Mutation' : 'Query' };
  const data = resolveChildren(rootCtx, op.sels, errors);
  if (errors.length > 0) return { data, errors };
  return { data };
}
async function handleGraphql(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<void> {
  if (!authed(req)) { sendJson(res, 401, { message: 'Bad credentials' }); return; }
  const parsed = parseJsonBody(body);
  if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
  const v = parsed.value;
  if (Array.isArray(v)) {
    const out = v.map((item) => {
      const o = asObj(item);
      return runGqlOp(asStr(o.query), asObj(o.variables));
    });
    sendJson(res, 200, out);
    return;
  }
  const o = asObj(v);
  sendJson(res, 200, runGqlOp(asStr(o.query), asObj(o.variables)));
}

// ---------- MCP ----------
const MCP_TOOLS: { name: string; description: string; inputSchema: { type: string; properties: Record<string, unknown>; required: string[] } }[] = [
  { name: 'create_repo', description: 'Create a repository for the viewer.', inputSchema: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, private: { type: 'boolean' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List issues in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_pull_request', description: 'Create a pull request.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
  { name: 'merge_pull_request', description: 'Squash-merge a pull request.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'integer' } }, required: ['owner', 'repo', 'pull_number'] } },
];
const MCP_SERVER_INFO = { name: 'makefun-forge', version: '1.0.0' };
function mcpPick(args: Record<string, unknown>, names: string[]): unknown {
  for (const n of names) if (args[n] !== undefined && args[n] !== null) return args[n];
  return undefined;
}
function mcpOwnerRepo(args: Record<string, unknown>): { owner: string; repo: string } {
  let owner = asStr(mcpPick(args, ['owner', 'owner_login', 'org', 'organization', 'user', 'user_login', 'login', 'account', 'namespace', 'owner_name']));
  let repo = asStr(mcpPick(args, ['repo', 'repository', 'repository_name', 'repo_name', 'repo_slug', 'project', 'project_name']));
  if (!repo) {
    const full = asStr(mcpPick(args, ['full_name', 'repo_full_name', 'repository_full_name', 'fullName']));
    if (full && full.includes('/')) { const parts = full.split('/'); owner = parts[0] as string; repo = parts.slice(1).join('/'); }
  }
  return { owner, repo };
}
function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id, result };
}
function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id, error: { code, message } };
}
function mcpToolResult(id: unknown, obj: unknown): Record<string, unknown> {
  const text = JSON.stringify(obj);
  return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], structuredContent: obj, isError: false } };
}
function mcpToolError(id: unknown, message: string): Record<string, unknown> {
  const obj = { error: message };
  return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(obj) }], structuredContent: obj, isError: true } };
}
async function handleMcp(req: IncomingMessage, res: ServerResponse, rawBody: Buffer): Promise<void> {
  const text = rawBody.toString('utf8');
  let msg: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
    msg = parsed as Record<string, unknown>;
  } catch {
    let id: unknown = null;
    const m = text.match(/"id"\s*:\s*("([^"]*)"|(-?\d+))/);
    if (m) {
      if (m[2] !== undefined) id = m[2];
      else if (m[3] !== undefined) id = parseInt(m[3], 10);
    }
    sendJson(res, 400, mcpError(id, -32700, 'Parse error'));
    return;
  }
  const id = msg.id ?? null;
  const method = asStr(msg.method);
  const params = asObj(msg.params);
  if (!msg.id && (method.startsWith('notifications/') || method === 'notifications/initialized')) {
    sendEmpty(res, 202);
    return;
  }
  if (method === 'server/discover') {
    sendJson(res, 200, mcpResult(id, {
      supportedVersions: ['2026-07-28'],
      capabilities: { tools: {} },
      serverInfo: MCP_SERVER_INFO,
      _meta: {
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO,
      },
    }));
    return;
  }
  if (method === 'initialize') {
    const offered = asStr(asObj(params).protocolVersion, '2025-11-25');
    const known = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    sendJson(res, 200, mcpResult(id, {
      protocolVersion: known.includes(offered) ? offered : '2025-11-25',
      capabilities: { tools: {} },
      serverInfo: MCP_SERVER_INFO,
    }));
    return;
  }
  if (method === 'ping') { sendJson(res, 200, mcpResult(id, {})); return; }
  if (method === 'tools/list') {
    if (!authed(req)) { errJson(res, 401, 'Bad credentials'); return; }
    sendJson(res, 200, mcpResult(id, { tools: MCP_TOOLS }));
    return;
  }
  if (method === 'tools/call') {
    if (!authed(req)) { errJson(res, 401, 'Bad credentials'); return; }
    const name = asStr(params.name);
    const args = asObj(params.arguments);
    const tool = MCP_TOOLS.find((t) => t.name === name);
    if (!tool) { sendJson(res, 200, mcpError(id, -32602, `Unknown tool: ${name}`)); return; }
    try {
      const result = mcpCall(tool.name, args);
      if (result === null) { sendJson(res, 200, mcpToolError(id, 'Missing required arguments')); return; }
      if (typeof result === 'string') { sendJson(res, 200, mcpToolError(id, result)); return; }
      sendJson(res, 200, mcpToolResult(id, result));
    } catch (e) {
      sendJson(res, 200, mcpToolError(id, e instanceof Error ? e.message : 'Tool error'));
    }
    return;
  }
  sendJson(res, 200, mcpError(id, -32601, `Method not found: ${method}`));
}
function mcpCall(name: string, args: Record<string, unknown>): unknown {
  if (name === 'create_repo') {
    const repoName = asStr(mcpPick(args, ['name', 'repo', 'repository', 'repository_name', 'repo_name']));
    if (!repoName) return null;
    const existing = getRepo(VIEWER_LOGIN, repoName);
    const r = existing ?? createRepo(repoName, asBool(mcpPick(args, ['private', 'is_private']), false), asStr(mcpPick(args, ['description', 'about', 'summary', 'body']), ''));
    return { id: repoGid(r), databaseId: r.id, name: r.name, full_name: `${r.owner}/${r.name}`, private: r.priv, default_branch: 'main', description: r.description, owner: { login: r.owner } };
  }
  if (name === 'get_repo') {
    const { owner, repo } = mcpOwnerRepo(args);
    if (!owner || !repo) return null;
    const r = owner === VIEWER_LOGIN ? getRepo(owner, repo) : undefined;
    if (!r) return `Repository not found: ${owner}/${repo}`;
    return { id: repoGid(r), databaseId: r.id, name: r.name, full_name: `${r.owner}/${r.name}`, private: r.priv, default_branch: 'main', description: r.description, owner: { login: r.owner } };
  }
  if (name === 'create_issue') {
    const { owner, repo } = mcpOwnerRepo(args);
    const title = asStr(mcpPick(args, ['title', 'issue_title', 'pr_title', 'pull_request_title', 'subject']));
    if (!owner || !repo || !title) return null;
    const r = owner === VIEWER_LOGIN ? getRepo(owner, repo) : undefined;
    if (!r) return `Repository not found: ${owner}/${repo}`;
    const issue: IssueRec = { id: nextEntityId++, number: r.nextIssue++, title, body: asStr(mcpPick(args, ['body', 'issue_body', 'description', 'content', 'text', 'comment']), ''), state: 'open', labels: [], comments: [] };
    r.issues.push(issue);
    return issueJson(issue);
  }
  if (name === 'list_issues') {
    const { owner, repo } = mcpOwnerRepo(args);
    if (!owner || !repo) return null;
    const r = owner === VIEWER_LOGIN ? getRepo(owner, repo) : undefined;
    if (!r) return `Repository not found: ${owner}/${repo}`;
    const state = asStr(mcpPick(args, ['state', 'status']), 'all');
    const list = r.issues.filter((i) => state === 'all' || i.state === state);
    return list.map(issueJson);
  }
  if (name === 'create_pull_request') {
    const { owner, repo } = mcpOwnerRepo(args);
    const title = asStr(mcpPick(args, ['title', 'issue_title', 'pr_title', 'pull_request_title', 'subject']));
    const head = asStr(mcpPick(args, ['head', 'head_ref', 'head_branch', 'pull_request_head', 'pr_head', 'source', 'source_ref', 'source_branch', 'from', 'from_branch', 'branch']));
    const base = asStr(mcpPick(args, ['base', 'base_ref', 'base_branch', 'pull_request_base', 'pr_base', 'target', 'target_ref', 'target_branch', 'into', 'into_branch']));
    if (!owner || !repo || !title || !head || !base) return null;
    const r = owner === VIEWER_LOGIN ? getRepo(owner, repo) : undefined;
    if (!r) return `Repository not found: ${owner}/${repo}`;
    const headSha = r.refs.get(`refs/heads/${head}`);
    const baseSha = r.refs.get(`refs/heads/${base}`);
    if (!headSha || !baseSha) return `Branch not found: ${head} or ${base}`;
    const pr: PrRec = {
      id: nextEntityId++, number: r.nextPr++, title, body: asStr(mcpPick(args, ['body', 'issue_body', 'description', 'content', 'text', 'comment']), ''),
      state: 'open', merged: false, merged_at: null, merge_commit_sha: null,
      head: { ref: head, sha: headSha }, base: { ref: base, sha: baseSha }, comments: [],
    };
    r.prs.push(pr);
    return prJson(pr);
  }
  if (name === 'merge_pull_request') {
    const { owner, repo } = mcpOwnerRepo(args);
    const numRaw = mcpPick(args, ['pull_number', 'pull_request_number', 'pr_number', 'number', 'issue_number', 'index']);
    const num = typeof numRaw === 'number' ? numRaw : parseInt(String(numRaw ?? ''), 10);
    if (!owner || !repo || !Number.isFinite(num)) return null;
    const r = owner === VIEWER_LOGIN ? getRepo(owner, repo) : undefined;
    if (!r) return `Repository not found: ${owner}/${repo}`;
    const pr = r.prs.find((p) => p.number === num);
    if (!pr) return `Pull request not found: ${num}`;
    if (!pr.merged) {
      const m = squashMerge(r, pr);
      if (!m.ok) return `Merge conflict on pull request ${num}`;
    }
    return prJson(pr);
  }
  return null;
}

// ---------- router ----------
export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', 'http://entry');
        const pathname = url.pathname;
        const method = req.method ?? 'GET';
        if (method === 'GET' && pathname === '/healthz') { sendJson(res, 200, { ok: true }); return; }
        const body = await readBody(req);
        if (pathname === '/api/graphql' && method === 'POST') { await handleGraphql(req, res, body); return; }
        if (pathname === '/mcp' && method === 'POST') { await handleMcp(req, res, body); return; }
        if (pathname.startsWith('/api/v3')) {
          const restPath = pathname === '/api/v3' ? '' : pathname.slice('/api/v3/'.length);
          const segs = restPath === '' ? [] : splitPath(`/${restPath}`);
          await handleRest(req, res, segs, url, body);
          return;
        }
        const segs = splitPath(pathname);
        if (segs.length >= 3 && (segs[1] as string).endsWith('.git')) {
          const r = gitRepo(segs);
          const sub = segs[2] as string;
          if (sub === 'info' && segs[3] === 'refs' && method === 'GET') {
            if (!r) { errJson(res, 404, 'Not Found'); return; }
            const service = url.searchParams.get('service') ?? '';
            if (service !== 'git-upload-pack' && service !== 'git-receive-pack') { errJson(res, 404, 'Not Found'); return; }
            infoRefs(req, res, r, service, url);
            return;
          }
          if (sub === 'git-upload-pack' && method === 'POST') {
            if (!r) { errJson(res, 404, 'Not Found'); return; }
            handleUploadPack(req, res, r, body);
            return;
          }
          if (sub === 'git-receive-pack' && method === 'POST') {
            if (!r) { errJson(res, 404, 'Not Found'); return; }
            handleReceivePack(req, res, r, body);
            return;
          }
          errJson(res, 404, 'Not Found');
          return;
        }
        errJson(res, 404, 'Not Found');
      } catch (e) {
        try { errJson(res, 500, e instanceof Error ? e.message : 'Internal error'); } catch { /* socket gone */ }
      }
    })();
  });
}
