import { inspectWasm } from "./wasm-inspector.js";

const sendProgress = (value, label) => self.postMessage({ type: "progress", value, label });
const sha256 = async bytes => [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
  .map(value => value.toString(16).padStart(2, "0")).join("");

self.onmessage = async event => {
  try {
    const bytes = new Uint8Array(event.data.buffer);
    sendProgress(12, "Parsing WebAssembly sections in background");
    let report = null;
    try {
      report = await inspectWasm(bytes);
    } catch (error) {
      self.postMessage({ type: "notice", message: "Metadata parser skipped unsupported details: " + error.message });
    }

    sendProgress(30, "Loading WebAssembly toolkit");
    const library = await import("https://esm.sh/wabt@1.0.37");
    const wabt = await (library.default || library)();

    sendProgress(52, "Validating module");
    const binary = wabt.readWasm(bytes, { readDebugNames: true });
    let wat;
    try {
      binary.validate();
      sendProgress(72, "Resolving function and export names");
      binary.generateNames();
      binary.applyNames();
      sendProgress(86, "Converting binary to WAT");
      wat = binary.toText({ foldExprs: false, inlineExport: false });
    } finally {
      binary.destroy();
    }

    sendProgress(95, "Calculating output fingerprints");
    const inputHash = report ? report.sha256 : await sha256(bytes);
    const watHash = await sha256(new TextEncoder().encode(wat));
    self.postMessage({ type: "done", report, wat, inputHash, watHash });
  } catch (error) {
    self.postMessage({ type: "error", message: error && error.message ? error.message : String(error) });
  }
};
