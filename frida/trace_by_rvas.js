/*
 * This script contains functions which can help 
 * with tracing functions of a binary by their RVAs.
 *
 * See example usage below.
 *
 * See ghidra/DumpFuncRVAs, ghidra/DumpFuncTreeRVAs, 
 * output of which can be inserted in this script
 *
 * author: LapTapk
*/

'use strict';

function findModuleByNameSubstring(nameSubstr) {
  const sub = nameSubstr.toLowerCase();
  const mods = Process.enumerateModules();
  let m = mods.find(x => x.name.toLowerCase() === sub);
  if (m) return m;
  m = mods.find(x => x.name.toLowerCase().includes(sub));
  if (m) return m;
  throw new Error(`Module not found: ${nameSubstr}`);
}

function bestSymbolString(addr) {
  try {
    const ds = DebugSymbol.fromAddress(addr);
    if (ds) {
      const name = ds.name || "";
      const mod = ds.moduleName || "";
      if (name.length > 0) return `${mod}!${name}`;
      return ds.toString();
    }
  } catch (_) {}
  return addr.toString();
}

function hookAddresses(module, rvas) {
  const base = module.base;
  const size = module.size;

  let hooked = 0;
  let failed = 0;

  const seen = new Set();

  for (const rva of rvas) {
    const addr = base.add(rva);

    const inRange =
      addr.compare(base) >= 0 &&
      addr.compare(base.add(size)) < 0;

    if (!inRange) {
      failed++;
      continue;
    }

    const key = addr.toString();
    if (seen.has(key)) continue;
    seen.add(key);

    try {
      Interceptor.attach(addr, {
        onEnter(args) {
          const rvaHere = ptr(this.context.pc).sub(base);
          const sym = bestSymbolString(ptr(this.context.pc));
          console.log(`[HIT] ${module.name}+${rvaHere} @ ${sym}`);
        }
      });
      hooked++;
    } catch (e) {
      failed++;
    }
    console.log(`hooked: ${rva}`)
  }

  console.log(`[+] Module: ${module.name} base=${base} size=0x${size.toString(16)}`);
  console.log(`[+] RVAs input: ${rvas.length}`);
  console.log(`[+] Hooked: ${hooked}, failed/out-of-range: ${failed}`);
}

(function main() {
/*
 * Example:
 *
 * const rvas = [0x1000, 0xdeadbeef, 0xc00fee, ...];
 * 
 * const moduleName = "mod.so";
 * const module = findModuleByNameSubstring(moduleName);
 *
 * hookAddresses(module, rvas);
 * */
})();
