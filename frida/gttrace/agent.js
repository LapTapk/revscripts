'use strict';

var followed = new Set();
var buf = [];
var follow = {}

var MAX = 2000;
var receiver;
var entryMod;
var entryRva;

var socket_;
var sendto_;
var close_;
var write_;

const AF_UNIX     = 1;
const SOCK_DGRAM  = 2;

var fd;
var dst;

/* ---------- export resolver (no static Module.findExportByName required) ---------- */

function findExportAny(sym) {
  // Fast path: scan exports (works everywhere, but O(modules * exports))
  for (const m of Process.enumerateModules()) {
    try {
      const exps = Module.enumerateExportsSync(m.name);
      for (const e of exps) {
        if (e.name === sym) return e.address;
      }
    } catch (_) {}
  }

  // Fallback: module-instance method
  for (const m of Process.enumerateModules()) {
    try {
      const mod = Process.getModuleByName(m.name);
      const p = mod.findExportByName(sym);
      if (p) return p;
    } catch (_) {}
  }

  return null;
}

function nf(sym, ret, args) {
  const p = findExportAny(sym);
  if (p === null) throw new Error("export not found: " + sym);
  return new NativeFunction(p, ret, args);
}
/* ---------- sockaddr_un helper ---------- */

function sockaddr_un(path) {
  const max = 108; // Linux sun_path
  const size = 2 + max;
  const sa = Memory.alloc(size);

  // zero
  sa.writeByteArray(new Uint8Array(size));

  // sa_family_t
  sa.writeU16(AF_UNIX);

  // sun_path (NUL-terminated)
  sa.add(2).writeUtf8String(path);

  return { sa, len: size };
}

/* ---------- socket setup ---------- */
function stderrLine(s) {
  const line = s + "\n";
  const buf = Memory.allocUtf8String(line);
  write_(2, buf, line.length);
}

/* ---------- send_to_server() replacement ---------- */

// Keep original send_to_server() if a controller ever attaches later


function send_to_server(payload, data) {
  let obj = { type: "send", payload, data };

  // Optional: attach raw bytes length marker if caller provided `data`
  // (Frida's second arg is typically an ArrayBuffer in controller mode)
  if (data !== undefined && data !== null) {
    try {
      if (data.byteLength !== undefined) obj.data_len = data.byteLength;
      else if (data.length !== undefined) obj.data_len = data.length;
      else obj.data_len = -1;
    } catch (_) {
      obj.data_len = -1;
    }
  }

  let line;
  try {
    line = JSON.stringify(obj) + "\n";
  } catch (e) {
    line = '{"type": "send", "payload": {"type": "status", "msg": "json_error"} }\n';
  }

  // Send datagram. If receiver is missing, send_to_serverto() returns -1 (ignored here).
  try {
    const buf = Memory.allocUtf8String(line);
    sendto_(fd, buf, line.length, 0, dst.sa, dst.len);
  } catch (e) {
    // last resort: local stderr
    try { stderrLine("sendto failed: " + e); } catch (_) {}
  }
};

function flush() {
  if (buf.length === 0) return;
  send_to_server({ type: "cf", items: buf, pid: Process.id });
  buf = [];
}

function emitCf(item) {
  buf.push(item);
  if (buf.length >= MAX) flush();
}

function startFollow(tidToFollow) {
  followed.add(tidToFollow);
  Stalker.follow(tidToFollow, {
    transform(iterator) {
      let insn;

      while ((insn = iterator.next()) !== null) {
        const tid = Process.getCurrentThreadId()
        if(entryMod && !follow[tid]) {
            iterator.keep();
            continue;
        }

        const from = ptr(insn.address);
        const mn = insn.mnemonic;
        if (mn === 'call' || mn.startsWith('j')) {
            const op0 = insn.operands[0];
            if (op0?.type === "reg") {
                const regName = op0.value;   

                iterator.putCallout(ctx => {
                  const target = ptr(ctx[regName]);
                  emitCf({from, target, tid: Process.getCurrentThreadId()});
                }); 
            } else if (op0?.type === "mem") {
                const v = op0.value;
                const baseName = v.base;
                const indexName = v.index;
                const scale = v.scale;
                const disp = v.disp;

                iterator.putCallout(ctx => {
                  const base = ptr(baseName ? ctx[baseName] : 0);
                  const index = ptr(indexName ? ctx[indexName] : 0);
                  const target = ptr(base.add(index * scale).add(disp)).readPointer();
                  emitCf({from, target, tid: Process.getCurrentThreadId()});
                }); 
            } else {
                iterator.putCallout(() => {
                  const target = ptr(op0.value);
                  emitCf({from, target, tid: Process.getCurrentThreadId()});
                }); 
            }
        }

        iterator.keep();
      }
    },
  });

  send_to_server({ type: "status", msg: `stalker_started tid: ${tidToFollow} pid: ${Process.id}` });
}

function stopFollow(tid) {
  if (!followed.has(tid)) return;
  Stalker.unfollow(tid);
  Stalker.flush();
  followed.delete(tid);
  send_to_server({ type: 'status', msg: `unfollow tid: ${tid} pid: ${Process.id}` });
}


function shutdown() {
    tobserver.detach()
    mobserver.detach()

    const tids = Array.from(followed);
    for(const tid of tids) {
        stopFollow(tid);
    }
    Stalker.flush();
    Stalker.garbageCollect();

    Interceptor.detachAll();
    send_to_server({ type: 'done' });
}

setInterval(flush, 50); 

rpc.exports = {
    init(stage, params) {
        receiver = params.receiver;
        entryMod = params.entryMod;
        entryRva = params.entryRva;
        if(entryRva) {
            entryRva = ptr(entryRva);
        }

        socket_ = nf("socket", "int", ["int", "int", "int"]);
        sendto_ = nf("sendto", "long", ["int", "pointer", "ulong", "int", "pointer", "uint"]);
        close_  = nf("close",  "int", ["int"]);
        write_  = nf("write",  "int", ["int", "pointer", "ulong"]); 

        fd = socket_(AF_UNIX, SOCK_DGRAM, 0);
        dst = sockaddr_un(receiver);

        const tobserver = Process.attachThreadObserver({
            onAdded(thread) {
                startFollow(thread.id);
            }
        });
        const mobserver = Process.attachModuleObserver( {
            onAdded(m) {
                send_to_server({
                    type: "mod",
                    remove: false,
                    start: m.base.toString(),
                    end: m.base.add(m.size).toString(),
                    name: m.name,
                    path: m.path,
                    pid: Process.id
                });

                if(m.name === entryMod) {
                    Interceptor.attach(entryRva.add(m.base), {
                        onEnter(args) {
                            console.log("===== REACHED ENTRY =====");
                            follow[Process.getCurrentThreadId()] = true;
                        },
                        onExit(_) {
                            console.log("===== REACHED  EXIT =====");
                            follow[Process.getCurrentThreadId()] = false;
                        }
                    });
                }
            },
            onRemoved(m) {
                send_to_server({
                    type: "mod",
                    remove: true,
                    start: m.base.toString(),
                    end: m.base.add(m.size).toString(),
                    name: m.name,
                    path: m.pathm,
                    pid: Process.id
                });
            }
        });
    }
}
