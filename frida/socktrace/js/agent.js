'use strict';

const CFG = JSON.parse('%(cfg)s');

// ---------- helpers ----------
function nowMs() { return (new Date()).getTime(); }

function sanitizeConnId(s) {
  return s.replace(/[^a-zA-Z0-9_.:@=\-+]/g, '_');
}

// ---------- native bindings ----------
const libcName = CFG.libc_name && CFG.libc_name.length ? CFG.libc_name : null;

function exp(name) {
  const m = Process.findModuleByName(libcName);
  const p = m ? m.findExportByName(name) : null;
  if (p === null) return Module.findExportByName(null, name);
  return p;
}

const p_send        = exp('send');
const p_recv        = exp('recv');
const p_read        = exp('read');
const p_write       = exp('write');
const p_close       = exp('close');
const p_dup         = exp('dup');
const p_dup2        = exp('dup2');
const p_dup3        = exp('dup3');
const p_fcntl       = exp('fcntl');

const p_bind        = exp('bind');
const p_listen      = exp('listen');     // optional
const p_accept      = exp('accept');
const p_accept4     = exp('accept4');

const p_getsockname = exp('getsockname');
const p_getpeername = exp('getpeername'); // optional

if (p_fcntl === null || p_getsockname === null) {
  send({ type: 'error', message: 'Required libc symbols missing: fcntl/getsockname' });
}

// int fcntl(int fd, int cmd, ...);
const fcntl = p_fcntl ? new NativeFunction(p_fcntl, 'int', ['int', 'int', 'int']) : null;
// int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
const getsockname = p_getsockname ? new NativeFunction(p_getsockname, 'int', ['int', 'pointer', 'pointer']) : null;
// int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
const getpeername = p_getpeername ? new NativeFunction(p_getpeername, 'int', ['int', 'pointer', 'pointer']) : null;

const AF_UNIX = 1; // Linux
const F_GETFD = 1;

const maxFds = CFG.max_fds || 4096;
const maxBytes = CFG.max_bytes || 4096;

const whitelist = new Set(CFG.socket_paths || []);

// serverListenFd -> boundPath (only if whitelisted, but can store all)
const listenMap = new Map();

// tracked connection fds (accepted fds) OR tracked client fds if you keep connect hooks
// fd -> { path, connId, createdAtMs }
const tracked = new Map();

function emitOpen(fd, path, connId, how) {
  send({ type: 'open', fd, path, conn_id: connId, how, ts_ms: nowMs() });
}

function emitClose(fd, connId, how) {
  send({ type: 'close', fd, conn_id: connId, how, ts_ms: nowMs() });
}

function trackFd(fd, path, how) {
  if (!whitelist.has(path)) return;
  const connId = sanitizeConnId(`${path}:fd=${fd}:t=${nowMs()}`);
  tracked.set(fd, { path, connId, createdAtMs: nowMs() });
  emitOpen(fd, path, connId, how);
}

function untrackFd(fd, how) {
  const rec = tracked.get(fd);
  if (rec) {
    tracked.delete(fd);
    emitClose(fd, rec.connId, how);
  }
  if (listenMap.has(fd)) {
    // if listening socket closed, forget mapping
    listenMap.delete(fd);
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

    // Abstract namespace: sun_path[0] == '\0' and then name bytes (not NUL-terminated)
    if (first === 0) {
      // Best-effort decode; stop at first 0 if present, else use maxPath-1
      const n = Math.max(0, maxPath - 1);
      if (n === 0) return '@';
      const raw = pathPtr.add(1).readByteArray(n);
      if (!raw) return '@';
      // Prefer UTF-8 but avoid junk beyond first NUL
      const u8 = new Uint8Array(raw);
      let end = 0;
      while (end < u8.length && u8[end] !== 0) end++;
      // decode printable-ish
      let s = '';
      for (let i = 0; i < end; i++) {
        const c = u8[i];
        if (c >= 32 && c <= 126) s += String.fromCharCode(c);
        else s += '\\x' + c.toString(16).padStart(2, '0');
      }
      return '@' + s;
    }

    // Filesystem socket: treat as bytes up to first NUL within maxPath
    const raw2 = pathPtr.readByteArray(maxPath);
    if (!raw2) return null;
    const u82 = new Uint8Array(raw2);
    let end2 = 0;
    while (end2 < u82.length && u82[end2] !== 0) end2++;
    if (end2 === 0) return null;

    // decode (paths typically ASCII; keep non-printable escaped)
    let out = '';
    for (let i = 0; i < end2; i++) {
      const c = u82[i];
      if (c >= 32 && c <= 126) out += String.fromCharCode(c);
      else out += '\\x' + c.toString(16).padStart(2, '0');
    }
    return out;
  } catch (_) {
    return null;
  }
}

function getUnixPathBySockname(fd) {
  if (!getsockname) return null;
  const bufSize = 256;
  const addr = Memory.alloc(bufSize);
  const lenp = Memory.alloc(4);
  lenp.writeU32(bufSize);

  const rc = getsockname(fd, addr, lenp);
  if (rc !== 0) return null;

  const outLen = lenp.readU32();
  return readSockaddrUnPath(addr, outLen);
}

function getUnixPathByPeer(fd) {
  if (!getpeername) return null;
  const bufSize = 256;
  const addr = Memory.alloc(bufSize);
  const lenp = Memory.alloc(4);
  lenp.writeU32(bufSize);

  const rc = getpeername(fd, addr, lenp);
  if (rc !== 0) return null;

  const outLen = lenp.readU32();
  return readSockaddrUnPath(addr, outLen);
}

// ---------- preexisting mapping (server-focused) ----------
function enumerateAlreadyOpenFdsServer() {
  if (!fcntl || !getsockname) return;

  for (let fd = 0; fd < maxFds; fd++) {
    const v = fcntl(fd, F_GETFD, 0);
    if (v < 0) continue;

    // Server side: local name (getsockname) is the listening/bound socket path.
    const localPath = getUnixPathBySockname(fd);
    if (localPath && whitelist.has(localPath)) {
      // We don't know if it's listen fd or accepted fd; track it anyway.
      // If it's a listening fd, IO hooks won't emit because no IO on it typically.
      // If it's an accepted fd, great.
      trackFd(fd, localPath, 'preexisting:getsockname');

      // Also, if it is a listening socket (likely), remember mapping
      listenMap.set(fd, localPath);
    }
  }

  send({ type: 'ready', tracked_fds: tracked.size, listen_fds: listenMap.size, ts_ms: nowMs() });
}

// ---------- server hooks (bind/listen/accept) ----------
function hookBindListenAccept() {
  // bind(fd, sockaddr*, addrlen) lets us record the listen fd -> path
  if (p_bind) {
    Interceptor.attach(p_bind, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.addr = args[1];
        this.len = args[2].toInt32();
        this.path = readSockaddrUnPath(this.addr, this.len);
      },
      onLeave(retval) {
        if (retval.toInt32() !== 0) return;
        if (!this.path) return;

        // Record mapping even if not whitelisted (optional); but only keep for whitelist to reduce noise.
        if (whitelist.has(this.path)) {
          listenMap.set(this.fd, this.path);
          // Optional: emit an "open" for listen socket itself:
          // trackFd(this.fd, this.path, 'bind:listenfd');
          send({ type: 'listen', fd: this.fd, path: this.path, how: 'bind', ts_ms: nowMs() });
        }
      }
    });
  }

  if (p_listen) {
    Interceptor.attach(p_listen, {
      onEnter(args) { this.fd = args[0].toInt32(); },
      onLeave(retval) {
        if (retval.toInt32() !== 0) return;

        // If we didn't catch bind() (already bound), resolve via getsockname
        if (!listenMap.has(this.fd)) {
          const localPath = getUnixPathBySockname(this.fd);
          if (localPath && whitelist.has(localPath)) {
            listenMap.set(this.fd, localPath);
            send({ type: 'listen', fd: this.fd, path: localPath, how: 'listen:getsockname', ts_ms: nowMs() });
          }
        }
      }
    });
  }

  function onAcceptLeave(listenFd, newFd, how) {
    if (newFd < 0) return;

    // Prefer mapping from listening fd; fallback to getsockname(newfd)
    let path = listenMap.get(listenFd) || null;
    if (!path) {
      path = getUnixPathBySockname(newFd);
      if (path && whitelist.has(path)) {
        // keep mapping for future accepts if it was actually a listen fd,
        // but here it's newfd so just proceed
      }
    }

    if (path && whitelist.has(path)) {
      trackFd(newFd, path, how);
    }
  }

  if (p_accept) {
    Interceptor.attach(p_accept, {
      onEnter(args) {
        this.listenFd = args[0].toInt32();
      },
      onLeave(retval) {
        const newFd = retval.toInt32();
        onAcceptLeave(this.listenFd, newFd, 'accept');
      }
    });
  }

  if (p_accept4) {
    Interceptor.attach(p_accept4, {
      onEnter(args) {
        this.listenFd = args[0].toInt32();
      },
      onLeave(retval) {
        const newFd = retval.toInt32();
        onAcceptLeave(this.listenFd, newFd, 'accept4');
      }
    });
  }
}

// ---------- close/dup ----------
function hookCloseAndDup() {
  if (p_close) {
    Interceptor.attach(p_close, {
      onEnter(args) { this.fd = args[0].toInt32(); },
      onLeave(_) { untrackFd(this.fd, 'close'); }
    });
  }

  function cloneTrack(oldfd, newfd, how) {
    const rec = tracked.get(oldfd);
    if (!rec) return;
    const path = rec.path;
    const connId = sanitizeConnId(`${path}:fd=${newfd}:t=${nowMs()}`);
    tracked.set(newfd, { path, connId, createdAtMs: nowMs() });
    emitOpen(newfd, path, connId, how);
  }

  if (p_dup) {
    Interceptor.attach(p_dup, {
      onEnter(args) { this.oldfd = args[0].toInt32(); },
      onLeave(retval) {
        const newfd = retval.toInt32();
        if (newfd >= 0) cloneTrack(this.oldfd, newfd, 'dup');
        // also propagate listenMap if duplicating listening socket
        if (newfd >= 0 && listenMap.has(this.oldfd)) listenMap.set(newfd, listenMap.get(this.oldfd));
      }
    });
  }

  if (p_dup2) {
    Interceptor.attach(p_dup2, {
      onEnter(args) { this.oldfd = args[0].toInt32(); this.newfd = args[1].toInt32(); },
      onLeave(retval) {
        const r = retval.toInt32();
        if (r >= 0) {
          untrackFd(this.newfd, 'dup2:overwrite');
          cloneTrack(this.oldfd, this.newfd, 'dup2');
          if (listenMap.has(this.oldfd)) listenMap.set(this.newfd, listenMap.get(this.oldfd));
        }
      }
    });
  }

  if (p_dup3) {
    Interceptor.attach(p_dup3, {
      onEnter(args) { this.oldfd = args[0].toInt32(); this.newfd = args[1].toInt32(); },
      onLeave(retval) {
        const r = retval.toInt32();
        if (r >= 0) {
          untrackFd(this.newfd, 'dup3:overwrite');
          cloneTrack(this.oldfd, this.newfd, 'dup3');
          if (listenMap.has(this.oldfd)) listenMap.set(this.newfd, listenMap.get(this.oldfd));
        }
      }
    });
  }
}

// ---------- data emit ----------
function emitData(fd, direction, bytes) {
  const rec = tracked.get(fd);
  if (!rec) return;
  if (bytes === null) return;

  let n = bytes.byteLength;
  if (n > maxBytes) {
    bytes = bytes.slice(0, maxBytes);
    n = maxBytes;
  }

  send({
    type: 'data',
    fd,
    conn_id: rec.connId,
    path: rec.path,
    direction,
    size: n,
    ts_ms: nowMs()
  }, bytes);
}

// ---------- IO hooks ----------
function hookIo() {
  if (p_send) {
    Interceptor.attach(p_send, {
      onEnter(args) {
        const fd = args[0].toInt32();
        if (!tracked.has(fd)) return;
        const buf = args[1];
        let len = args[2].toUInt32();
        if (len === 0) return;
        if (len > maxBytes) len = maxBytes;
        try { emitData(fd, 'out', buf.readByteArray(len)); } catch (_) {}
      }
    });
  }

  if (p_write) {
    Interceptor.attach(p_write, {
      onEnter(args) {
        const fd = args[0].toInt32();
        if (!tracked.has(fd)) return;
        const buf = args[1];
        let len = args[2].toUInt32();
        if (len === 0) return;
        if (len > maxBytes) len = maxBytes;
        try { emitData(fd, 'out', buf.readByteArray(len)); } catch (_) {}
      }
    });
  }

  if (p_recv) {
    Interceptor.attach(p_recv, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        if (!tracked.has(this.fd)) { this.fd = -1; return; }
        this.buf = args[1];
      },
      onLeave(retval) {
        if (this.fd < 0) return;
        const n = retval.toInt32();
        if (n <= 0) return;
        const cap = (n > maxBytes) ? maxBytes : n;
        try { emitData(this.fd, 'in', this.buf.readByteArray(cap)); } catch (_) {}
      }
    });
  }

  if (p_read) {
    Interceptor.attach(p_read, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        if (!tracked.has(this.fd)) { this.fd = -1; return; }
        this.buf = args[1];
      },
      onLeave(retval) {
        if (this.fd < 0) return;
        const n = retval.toInt32();
        if (n <= 0) return;
        const cap = (n > maxBytes) ? maxBytes : n;
        try { emitData(this.fd, 'in', this.buf.readByteArray(cap)); } catch (_) {}
      }
    });
  }
}

// ---------- init ----------
(function main() {
  // Server-side: preexisting scan should use getsockname(), not getpeername()
  enumerateAlreadyOpenFdsServer();

  // Server-side lifecycle hooks
  hookBindListenAccept();

  hookCloseAndDup();
  hookIo();

  send({
    type: 'init',
    mode: 'server',
    libc_name: libcName,
    whitelist_count: whitelist.size,
    max_fds: maxFds,
    max_bytes: maxBytes,
    ts_ms: nowMs()
  });
})();
