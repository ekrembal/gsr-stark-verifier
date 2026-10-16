// Runs one pr-sdk-wasm command per message in a fresh WASI instance over an in-memory /work
// directory. Inputs and outputs (including private witnesses) never leave this worker except
// back to the page that sent them.
import { WASI, File, OpenFile, ConsoleStdout, PreopenDirectory, WASIProcExit } from "./vendor/package/dist/index.js";

let modulePromise = null;

function compile(url) {
  if (!modulePromise) {
    modulePromise = (async () => {
      const t = performance.now();
      const module = await WebAssembly.compileStreaming(fetch(url));
      return { module, compile_ms: performance.now() - t };
    })();
  }
  return modulePromise;
}

self.onmessage = async (ev) => {
  const { id, url, args, files } = ev.data;
  const stdout = [];
  const log = (line) => self.postMessage({ id, log: line });
  try {
    const { module, compile_ms } = await compile(url);
    const contents = new Map(Object.entries(files).map(([name, bytes]) => [name, new File(bytes)]));
    const work = new PreopenDirectory("/work", contents);
    const fds = [
      new OpenFile(new File([])),
      ConsoleStdout.lineBuffered((l) => stdout.push(l)),
      ConsoleStdout.lineBuffered(log),
      work,
    ];
    const wasi = new WASI(["pr-sdk-wasm", ...args], [], fds);
    const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: wasi.wasiImport });
    const t = performance.now();
    let exit, trap = null;
    try {
      exit = wasi.start(instance);
    } catch (e) {
      trap = String(e && e.message ? e.message : e);
      exit = e instanceof WASIProcExit ? e.code : -1;
    }
    const wall_ms = performance.now() - t;
    const out = {};
    for (const [name, inode] of work.dir.contents) {
      if (inode instanceof File) out[name] = inode.data;
    }
    self.postMessage({
      id, done: true, exit, trap, wall_ms, compile_ms, stdout,
      memory_bytes: instance.exports.memory.buffer.byteLength, files: out,
    });
  } catch (e) {
    self.postMessage({ id, done: true, exit: -1, trap: String(e && e.message ? e.message : e), stdout });
  }
};
