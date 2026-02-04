'use strict';

let followed = new Set();
let buf = [];
const MAX = 2000;
const entryMod = %(entry_mod)s
const entryRva = ptr(%(entry_rva)s ?? 0)
let follow = {}

function flush() {
  if (buf.length === 0) return;
  send({ type: "cf", items: buf });
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

  send({ type: "status", msg: `stalker_started tid: ${tidToFollow}` });
}

function stopFollow(tid) {
  if (!followed.has(tid)) return;
  Stalker.unfollow(tid);
  Stalker.flush();
  followed.delete(tid);
  send({ type: 'status', msg: 'unfollow', tid });
}

const tobserver = Process.attachThreadObserver({
    onAdded(thread) {
        startFollow(thread.id);
    }
});

const mobserver = Process.attachModuleObserver( {
    onAdded(m) {
        send({
            type: "mod",
            remove: 0,
            start: m.base.toString(),
            end: m.base.add(m.size).toString(),
            name: m.name,
            path: m.path
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
        send({
            type: "mod",
            remove: 1,
            start: m.base.toString(),
            end: m.base.add(m.size).toString(),
            name: m.name,
            path: m.path
        });
    }
});

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
    send({ type: 'done' });
}

setInterval(flush, 50); 

rpc.exports = {
  cleanup() {
    shutdown();
    return true;
  }
}
