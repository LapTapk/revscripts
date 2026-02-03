'use strict';

/*
  Server-side UNIX socket tracer streaming events+payload to a user-specified
  UNIX socket. Output uses native socket(), connect(), sendto().

  Constraints satisfied:
  - rpc.exports.init(_, params) initializes the whole system
  - all output goes to params.out_socket_path (AF_UNIX)
  - export resolution scans module instances only (no Module.findExportByName(null,...))
  - does NOT trace traffic produced by the agent itself (suppression guard + exclude outFd)
  - uses ptr.write*() APIs only (no Memory.write*)
*/

let STATE = {
  inited: false,

  // config
  libcName: null,
  maxFds: 4096,
  maxBytes: 4096,
  whitelist: new Set(),

  // maps
  listenMap: new Map(), // listenFd -> path
  tracked: new Map(),   // fd -> { path, connId, createdAtMs }

  // output socket
  outFd: -1,
  outPath: null,
  outSockType: 2, // SOCK_DGRAM
  outConnected: false,

  // suppression: while we emit, ignore hooks in this thread
  suppressTid: new Set(),

  // interceptor handles (optional detach if needed)
  hooks: [],
};

/* ---------------- helpers ---------------- */

function nowMs() { return (new Date()).getTime(); }

function sanitizeConnId(s) {
  return s.replace(/[^a-zA-Z0-9_.:@=\-+]/g, '_');
}

function tid() {
  try { return Process.getCurrentThreadId(); } catch (_) { return -1; }
}

function withSuppressed(fn) {
  const t = tid();
  STATE.suppressTid.add(t);
  try { return fn(); } finally { STATE.suppressTid.delete(t); }
}

function isSuppressed() {
  const t = tid();
  return STATE.suppressTid.has(t);
}

/* ---------------- export resolver (module instances only) ---------------- */

const exportCache = new Map();

function findExportAny(sym, preferredModuleName /* optional */) {
  const key = preferredModuleName ? (preferredModuleName + '!' + sym) : sym;
  if (exportCache.has(key)) return exportCache.get(key);

  // preferred module fast-path
  if (preferredModuleName) {
    try {
      const m0 = Process.findModuleByName(preferredModuleName);
      if (m0) {
        const mod0 = Process.getModuleByName(m0.name);
        const p0 = mod0.findExportByName(sym);
        if (p0) { exportCache.set(key, p0); return p0; }
      }
    } catch (_) {}
  }

  // scan all module instances
  const mods = Process.enumerateModules();
  for (let i = 0; i < mods.length; i++) {
    const m = mods[i];
    try {
      const mod = Process.getModuleByName(m.name);
      const p = mod.findExportByName(sym);
      if (p) { exportCache.set(key, p); return p; }
    } catch (_) {}
  }

  exportCache.set(key, null);
  return null;
}

/* ---------------- native bindings ---------------- */

let p_send = null, p_recv = null, p_read = null, p_write = null, p_close = null;
let p_dup = null, p_dup2 = null, p_dup3 = null, p_fcntl = null;
let p_bind = null, p_listen = null, p_accept = null, p_accept4 = null;
let p_getsockname = null, p_getpeername = null;

let p_socket = null, p_connect = null, p_sendto = null;

let nf_fcntl = null, nf_getsockname = null, nf_getpeername = null;
let nf_socket = null, nf_connect = null, nf_sendto = null;

const AF_UNIX = 1;
const F_GETFD = 1;

const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;

/* ---------------- sockaddr_un helpers (ptr.write* only) ---------------- */

function sockaddrUnFromPath(path) {
  // sockaddr_un (Linux):
  //   u16 sun_family
  //   char sun_path[108]
  const cap = 2 + 108;
  const addr = Memory.alloc(cap);

  // zero it using ptr.writeU8()
  for (let i = 0; i < cap; i++) addr.add(i).writeU8(0);
  addr.writeU16(AF_UNIX);

  const sun = addr.add(2);

  if (path.startsWith('@')) {
    // abstract namespace: first byte is 0, then bytes of name (not NUL-terminated)
    const name = path.slice(1);
    sun.writeU8(0);
    const max = 107;
    const n = Math.min(name.length, max);
    for (let i = 0; i < n; i++) {
      sun.add(1 + i).writeU8(name.charCodeAt(i) & 0xff);
    }
    return { addr, len: 2 + 1 + n };
  } else {
    // filesystem path: NUL-terminated
    const max = 107;
    const n = Math.min(path.length, max);
    for (let i = 0; i < n; i++) {
      sun.add(i).writeU8(path.charCodeAt(i) & 0xff);
    }
    sun.add(n).writeU8(0);
    // Use full size; kernel ignores trailing zeros
    return { addr, len: cap };
  }
}

function readSockaddrUnPath(addrPtr, addrLen) {
  if (addrPtr.isNull() || addrLen < 2) return null;
  try {
    const fam = addrPtr.readU16();
    if (fam !== AF_UNIX) return null;

    const pathPtr = addrPtr.add(2);
    const maxPath = Math.min(108, addrLen - 2);
    if (maxPath <= 0) return null;

    const first = pathPtr.readU8();

    if (first === 0) {
      // abstract namespace
      const n = Math.max(0, maxPath - 1);
      if (n === 0) return '@';
      const raw = pathPtr.add(1).readByteArray(n);
      if (!raw) return '@';
      const u8 = new Uint8Array(raw);
      let end = 0;
      while (end < u8.length && u8[end] !== 0) end++;
      let s = '';
      for (let i = 0; i < end; i++) {
        const c = u8[i];
        if (c >= 32 && c <= 126) s += String.fromCharCode(c);
        else s += '\\x' + c.toString(16).padStart(2, '0');
      }
      return '@' + s;
    } else {
      // filesystem path
      const raw2 = pathPtr.readByteArray(maxPath);
      if (!raw2) return null;
      const u82 = new Uint8Array(raw2);
      let end2 = 0;
      while (end2 < u82.length && u82[end2] !== 0) end2++;
      if (end2 === 0) return null;

      let out = '';
      for (let i = 0; i < end2; i++) {
        const c = u82[i];
        if (c >= 32 && c <= 126) out += String.fromCharCode(c);
        else out += '\\x' + c.toString(16).padStart(2, '0');
      }
      return out;
    }
  } catch (_) {
    return null;
  }
}

function getUnixPathBySockname(fd) {
  if (!nf_getsockname) return null;

  const bufSize = 256;
  const addr = Memory.alloc(bufSize);
  const lenp = Memory.alloc(4);
  lenp.writeU32(bufSize);

  const rc = nf_getsockname(fd, addr, lenp);
  if (rc !== 0) return null;

  const outLen = lenp.readU32();
  return readSockaddrUnPath(addr, outLen);
}

/* ---------------- output framing ---------------- */

function u16le(p, v) { p.writeU16(v & 0xffff); }
function u32le(p, v) { p.writeU32(v >>> 0); }

// Binary datagram frame:
//  magic(4) 'GTTR' = 0x52545447
//  ver(1) = 1
//  type(1): 1=open 2=close 3=listen 4=data 5=ready 6=init 7=error
//  flags(2): bit0=has_payload
//  ts_ms(u64)  [stored as two u32: lo, hi] to avoid i64 type hassles
//  fd(i32)
//  dir(u8) 0=none 1=in 2=out
//  reserved(3)
//  path_len(u16) connid_len(u16) payload_len(u32)
//  path bytes
//  connId bytes
//  payload bytes (optional)
const MAGIC = 0x52545447; // 'GTTR'
const VER = 1;

function writeU64As2U32(p, ms) {
  // ms fits in 53 bits; split into lo/hi 32
  const lo = (ms >>> 0);
  const hi = ((ms / 0x100000000) >>> 0);
  p.writeU32(lo);
  p.add(4).writeU32(hi);
}

function sendFrame(type, fd, dir, pathStr, connIdStr, payload /* ArrayBuffer|null */) {
  if (STATE.outFd < 0 || !nf_sendto) return;

  const t = nowMs();
  const pathBytes = pathStr ? pathStr : '';
  const connBytes = connIdStr ? connIdStr : '';

  // encode ASCII-ish (same approach as your sockaddr decoding: raw bytes)
  const pathLen = pathBytes.length;
  const connLen = connBytes.length;

  let payloadLen = 0;
  let payloadView = null;
  if (payload) {
    payloadLen = payload.byteLength >>> 0;
    payloadView = new Uint8Array(payload);
  }

  const headerLen =
    4 + 1 + 1 + 2 + // magic, ver, type, flags
    8 +             // ts_ms (lo/hi u32)
    4 +             // fd
    1 + 3 +         // dir + reserved
    2 + 2 + 4;      // path_len, connid_len, payload_len

  const total = headerLen + pathLen + connLen + payloadLen;
  const buf = Memory.alloc(total);

  let off = 0;
  buf.add(off).writeU32(MAGIC); off += 4;
  buf.add(off).writeU8(VER); off += 1;
  buf.add(off).writeU8(type & 0xff); off += 1;

  const flags = payloadLen ? 1 : 0;
  buf.add(off).writeU16(flags); off += 2;

  writeU64As2U32(buf.add(off), t); off += 8;

  buf.add(off).writeS32(fd | 0); off += 4;

  buf.add(off).writeU8(dir & 0xff); off += 1;
  buf.add(off).writeU8(0); buf.add(off + 1).writeU8(0); buf.add(off + 2).writeU8(0); off += 3;

  buf.add(off).writeU16(pathLen & 0xffff); off += 2;
  buf.add(off).writeU16(connLen & 0xffff); off += 2;
  buf.add(off).writeU32(payloadLen >>> 0); off += 4;

  for (let i = 0; i < pathLen; i++) buf.add(off + i).writeU8(pathBytes.charCodeAt(i) & 0xff);
  off += pathLen;

  for (let i = 0; i < connLen; i++) buf.add(off + i).writeU8(connBytes.charCodeAt(i) & 0xff);
  off += connLen;

  if (payloadLen) {
    for (let i = 0; i < payloadLen; i++) buf.add(off + i).writeU8(payloadView[i]);
    off += payloadLen;
  }

  withSuppressed(() => {
    // sendto(outFd, buf, total, 0, NULL, 0) since we connect()'d a DGRAM socket
    nf_sendto(STATE.outFd, buf, total, 0, ptr(0), 0);
  });
}

/* ---------------- emit API (no send()) ---------------- */

function emitError(msg) {
  sendFrame(7, -1, 0, '', msg || '', null);
}
function emitInit(meta) {
  sendFrame(6, -1, 0, '', meta || '', null);
}
function emitReady(trackedCount, listenCount) {
  sendFrame(5, -1, 0, '', `tracked=${trackedCount};listen=${listenCount}`, null);
}
function emitListen(fd, path, how) {
  sendFrame(3, fd, 0, path, how || '', null);
}
function emitOpen(fd, path, connId, how) {
  sendFrame(1, fd, 0, path, `${connId}|${how || ''}`, null);
}
function emitClose(fd, connId, how) {
  sendFrame(2, fd, 0, '', `${connId}|${how || ''}`, null);
}
function emitData(fd, direction, path, connId, bytes) {
  const dir = (direction === 'in') ? 1 : 2;
  sendFrame(4, fd, dir, path, connId, bytes);
}

/* ---------------- tracking ---------------- */

function trackFd(fd, path, how) {
  if (STATE.whitelist.size && !STATE.whitelist.has(path)) return;
  if (fd === STATE.outFd) return; // never track our own output socket
  const connId = sanitizeConnId(`${path}:fd=${fd}:t=${nowMs()}`);
  STATE.tracked.set(fd, { path, connId, createdAtMs: nowMs() });
  emitOpen(fd, path, connId, how);
}

function untrackFd(fd, how) {
  const rec = STATE.tracked.get(fd);
  if (rec) {
    STATE.tracked.delete(fd);
    emitClose(fd, rec.connId, how);
  }
  if (STATE.listenMap.has(fd)) STATE.listenMap.delete(fd);
}

/* ---------------- preexisting mapping (server-focused) ---------------- */

function enumerateAlreadyOpenFdsServer() {
  if (!nf_fcntl || !nf_getsockname) return;

  for (let fd = 0; fd < STATE.maxFds; fd++) {
    const v = nf_fcntl(fd, F_GETFD, 0);
    if (v < 0) continue;

    if (fd === STATE.outFd) continue;

    const localPath = getUnixPathBySockname(fd);
    if (localPath) {
      trackFd(fd, localPath, 'preexisting:getsockname');
      STATE.listenMap.set(fd, localPath);
    }
  }

  emitReady(STATE.tracked.size, STATE.listenMap.size);
}

/* ---------------- hooks ---------------- */

function attachHook(addr, spec) {
  if (!addr) return;
  const h = Interceptor.attach(addr, spec);
  STATE.hooks.push(h);
}

function hookBindListenAccept() {
  if (p_bind) {
    attachHook(p_bind, {
      onEnter(args) {
        if (isSuppressed()) { this.s = true; return; }
        this.fd = args[0].toInt32();
        if (this.fd === STATE.outFd) { this.s = true; return; }
        this.addr = args[1];
        this.len = args[2].toInt32();
        this.path = readSockaddrUnPath(this.addr, this.len);
      },
      onLeave(retval) {
        if (this.s) return;
        if (retval.toInt32() !== 0) return;
        if (!this.path) return;

        if (!STATE.whitelist.size || STATE.whitelist.has(this.path)) {
          STATE.listenMap.set(this.fd, this.path);
          emitListen(this.fd, this.path, 'bind');
        }
      }
    });
  }

  if (p_listen) {
    attachHook(p_listen, {
      onEnter(args) {
        if (isSuppressed()) { this.s = true; return; }
        this.fd = args[0].toInt32();
        if (this.fd === STATE.outFd) this.s = true;
      },
      onLeave(retval) {
        if (this.s) return;
        if (retval.toInt32() !== 0) return;

        if (!STATE.listenMap.has(this.fd)) {
          const localPath = getUnixPathBySockname(this.fd);
          if (localPath && (!STATE.whitelist.size || STATE.whitelist.has(localPath))) {
            STATE.listenMap.set(this.fd, localPath);
            emitListen(this.fd, localPath, 'listen:getsockname');
          }
        }
      }
    });
  }

  function onAcceptLeave(listenFd, newFd, how) {
    if (newFd < 0) return;
    if (newFd === STATE.outFd) return;

    let path = STATE.listenMap.get(listenFd) || null;
    if (!path) {
      path = getUnixPathBySockname(newFd);
    }
    if (path) trackFd(newFd, path, how);
  }

  if (p_accept) {
    attachHook(p_accept, {
      onEnter(args) {
        if (isSuppressed()) { this.s = true; return; }
        this.listenFd = args[0].toInt32();
        if (this.listenFd === STATE.outFd) this.s = true;
      },
      onLeave(retval) {
        if (this.s) return;
        onAcceptLeave(this.listenFd, retval.toInt32(), 'accept');
      }
    });
  }

  if (p_accept4) {
    attachHook(p_accept4, {
      onEnter(args) {
        if (isSuppressed()) { this.s = true; return; }
        this.listenFd = args[0].toInt32();
        if (this.listenFd === STATE.outFd) this.s = true;
      },
      onLeave(retval) {
        if (this.s) return;
        onAcceptLeave(this.listenFd, retval.toInt32(), 'accept4');
      }
    });
  }
}

function hookCloseAndDup() {
  if (p_close) {
    attachHook(p_close, {
      onEnter(args) {
        if (isSuppressed()) { this.s = true; return; }
        this.fd = args[0].toInt32();
        if (this.fd === STATE.outFd) { this.s = true; return; }
      },
      onLeave(_) {
        if (this.s) return;
        untrackFd(this.fd, 'close');
      }
    });
  }

  function cloneTrack(oldfd, newfd, how) {
    const rec = STATE.tracked.get(oldfd);
    if (!rec) return;
    if (newfd === STATE.outFd) return;

    const path = rec.path;
    const connId = sanitizeConnId(`${path}:fd=${newfd}:t=${nowMs()}`);
    STATE.tracked.set(newfd, { path, connId, createdAtMs: nowMs() });
    emitOpen(newfd, path, connId, how);
  }

  if (p_dup) {
    attachHook(p_dup, {
      onEnter(args) {
        if (isSuppressed()) { this.s = true; return; }
        this.oldfd = args[0].toInt32();
        if (this.oldfd === STATE.outFd) this.s = true;
      },
      onLeave(retval) {
        if (this.s) return;
        const newfd = retval.toInt32();
        if (newfd >= 0) cloneTrack(this.oldfd, newfd, 'dup');
        if (newfd >= 0 && STATE.listenMap.has(this.oldfd))
          STATE.listenMap.set(newfd, STATE.listenMap.get(this.oldfd));
      }
    });
  }

  if (p_dup2) {
    attachHook(p_dup2, {
      onEnter(args) {
        if (isSuppressed()) { this.s = true; return; }
        this.oldfd = args[0].toInt32();
        this.newfd = args[1].toInt32();
        if (this.oldfd === STATE.outFd || this.newfd === STATE.outFd) this.s = true;
      },
      onLeave(retval) {
        if (this.s) return;
        const r = retval.toInt32();
        if (r >= 0) {
          untrackFd(this.newfd, 'dup2:overwrite');
          cloneTrack(this.oldfd, this.newfd, 'dup2');
          if (STATE.listenMap.has(this.oldfd))
            STATE.listenMap.set(this.newfd, STATE.listenMap.get(this.oldfd));
        }
      }
    });
  }

  if (p_dup3) {
    attachHook(p_dup3, {
      onEnter(args) {
        if (isSuppressed()) { this.s = true; return; }
        this.oldfd = args[0].toInt32();
        this.newfd = args[1].toInt32();
        if (this.oldfd === STATE.outFd || this.newfd === STATE.outFd) this.s = true;
      },
      onLeave(retval) {
        if (this.s) return;
        const r = retval.toInt32();
        if (r >= 0) {
          untrackFd(this.newfd, 'dup3:overwrite');
          cloneTrack(this.oldfd, this.newfd, 'dup3');
          if (STATE.listenMap.has(this.oldfd))
            STATE.listenMap.set(this.newfd, STATE.listenMap.get(this.oldfd));
        }
      }
    });
  }
}

function hookIo() {
  // Important: do not trace our own outFd, and suppress while emitting to avoid recursion.

  if (p_send) {
    attachHook(p_send, {
      onEnter(args) {
        if (isSuppressed()) return;
        const fd = args[0].toInt32();
        if (fd === STATE.outFd) return;
        const rec = STATE.tracked.get(fd);
        if (!rec) return;

        const buf = args[1];
        let len = args[2].toUInt32();
        if (len === 0) return;
        if (len > STATE.maxBytes) len = STATE.maxBytes;

        try {
          const bytes = buf.readByteArray(len);
          if (bytes) emitData(fd, 'out', rec.path, rec.connId, bytes);
        } catch (_) {}
      }
    });
  }

  if (p_write) {
    attachHook(p_write, {
      onEnter(args) {
        if (isSuppressed()) return;
        const fd = args[0].toInt32();
        if (fd === STATE.outFd) return;
        const rec = STATE.tracked.get(fd);
        if (!rec) return;

        const buf = args[1];
        let len = args[2].toUInt32();
        if (len === 0) return;
        if (len > STATE.maxBytes) len = STATE.maxBytes;

        try {
          const bytes = buf.readByteArray(len);
          if (bytes) emitData(fd, 'out', rec.path, rec.connId, bytes);
        } catch (_) {}
      }
    });
  }

  if (p_recv) {
    attachHook(p_recv, {
      onEnter(args) {
        if (isSuppressed()) { this.s = true; return; }
        this.fd = args[0].toInt32();
        if (this.fd === STATE.outFd) { this.s = true; return; }
        this.rec = STATE.tracked.get(this.fd);
        if (!this.rec) { this.s = true; return; }
        this.buf = args[1];
      },
      onLeave(retval) {
        if (this.s) return;
        const n = retval.toInt32();
        if (n <= 0) return;
        const cap = (n > STATE.maxBytes) ? STATE.maxBytes : n;
        try {
          const bytes = this.buf.readByteArray(cap);
          if (bytes) emitData(this.fd, 'in', this.rec.path, this.rec.connId, bytes);
        } catch (_) {}
      }
    });
  }

  if (p_read) {
    attachHook(p_read, {
      onEnter(args) {
        if (isSuppressed()) { this.s = true; return; }
        this.fd = args[0].toInt32();
        if (this.fd === STATE.outFd) { this.s = true; return; }
        this.rec = STATE.tracked.get(this.fd);
        if (!this.rec) { this.s = true; return; }
        this.buf = args[1];
      },
      onLeave(retval) {
        if (this.s) return;
        const n = retval.toInt32();
        if (n <= 0) return;
        const cap = (n > STATE.maxBytes) ? STATE.maxBytes : n;
        try {
          const bytes = this.buf.readByteArray(cap);
          if (bytes) emitData(this.fd, 'in', this.rec.path, this.rec.connId, bytes);
        } catch (_) {}
      }
    });
  }
}

/* ---------------- init plumbing ---------------- */

function resolveAllSymbols() {
  const libcName = STATE.libcName;

  // tracer targets
  p_send        = findExportAny('send', libcName);
  p_recv        = findExportAny('recv', libcName);
  p_read        = findExportAny('read', libcName);
  p_write       = findExportAny('write', libcName);
  p_close       = findExportAny('close', libcName);
  p_dup         = findExportAny('dup', libcName);
  p_dup2        = findExportAny('dup2', libcName);
  p_dup3        = findExportAny('dup3', libcName);
  p_fcntl       = findExportAny('fcntl', libcName);

  p_bind        = findExportAny('bind', libcName);
  p_listen      = findExportAny('listen', libcName);
  p_accept      = findExportAny('accept', libcName);
  p_accept4     = findExportAny('accept4', libcName);

  p_getsockname = findExportAny('getsockname', libcName);
  p_getpeername = findExportAny('getpeername', libcName);

  // output syscalls (not necessarily in same module name; still scan all)
  p_socket      = findExportAny('socket', libcName);
  p_connect     = findExportAny('connect', libcName);
  p_sendto      = findExportAny('sendto', libcName);

  if (!p_fcntl || !p_getsockname) emitError('Required libc symbols missing: fcntl/getsockname');
  if (!p_socket || !p_connect || !p_sendto) emitError('Required libc symbols missing: socket/connect/sendto');

  nf_fcntl       = p_fcntl       ? new NativeFunction(p_fcntl,       'int', ['int', 'int', 'int']) : null;
  nf_getsockname = p_getsockname ? new NativeFunction(p_getsockname, 'int', ['int', 'pointer', 'pointer']) : null;
  nf_getpeername = p_getpeername ? new NativeFunction(p_getpeername, 'int', ['int', 'pointer', 'pointer']) : null;

  nf_socket      = p_socket      ? new NativeFunction(p_socket,      'int', ['int', 'int', 'int']) : null;
  nf_connect     = p_connect     ? new NativeFunction(p_connect,     'int', ['int', 'pointer', 'int']) : null;
  nf_sendto      = p_sendto      ? new NativeFunction(p_sendto,      'int', ['int', 'pointer', 'int', 'int', 'pointer', 'int']) : null;

  return true;
}

function openOutSocket(outPath, sockType) {
  if (!nf_socket || !nf_connect) return -1;
  const fd = nf_socket(AF_UNIX, sockType, 0);
  if (fd < 0) return -1;

  const sa = sockaddrUnFromPath(outPath);
  const rc = nf_connect(fd, sa.addr, sa.len);
  if (rc !== 0) {
    // for DGRAM, connect() to non-existent peer will fail until peer exists
    // but still keep fd; caller decides.
  }
  return fd;
}

/* ---------------- RPC entrypoint ---------------- */

rpc.exports = {
  init(_ /* ignored */, params) {
    if (STATE.inited) return true;

    // params:
    //  - max_fds: optional (int)
    //  - max_bytes: optional (int)
    //  - socket_paths: array of UNIX socket paths to trace (whitelist)
    //  - out_socket_path: required (string) where we send our datagrams
    //  - out_sock_type: optional: "dgram" | "stream" (default dgram)

    if (!params || typeof params !== 'object') throw new Error('params must be an object');
    if (!params.out_socket_path || typeof params.out_socket_path !== 'string')
      throw new Error('params.out_socket_path is required');

    STATE.maxFds = params.max_fds ? (params.max_fds | 0) : STATE.maxFds;
    STATE.maxBytes = params.max_bytes ? (params.max_bytes | 0) : STATE.maxBytes;
    STATE.whitelist = new Set(params.socket_paths || []);

    STATE.outPath = params.out_socket_path;
    const t = (params.out_sock_type === 'stream') ? SOCK_STREAM : SOCK_DGRAM;
    STATE.outSockType = t;

    resolveAllSymbols();

    // open output socket early, so we can avoid tracing it
    STATE.outFd = openOutSocket(STATE.outPath, STATE.outSockType);
    if (STATE.outFd < 0) emitError('Failed to create out socket fd');
    else emitInit(`mode=server;out=${STATE.outPath};socktype=${STATE.outSockType};whitelist=${STATE.whitelist.size}`);

    // preexisting scan and hooks
    enumerateAlreadyOpenFdsServer();
    hookBindListenAccept();
    hookCloseAndDup();
    hookIo();

    STATE.inited = true;
    return true;
  }
};
