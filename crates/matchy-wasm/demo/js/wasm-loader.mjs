import init, {
  Database,
  DatabaseBuilder,
  ExtractorBuilder,
  version,
} from "../pkg/matchy_wasm.js";

let initPromise = null;

export { Database, DatabaseBuilder, ExtractorBuilder, version };

export function initMatchyWasm() {
  if (!initPromise) {
    initPromise = init().catch((error) => {
      initPromise = null;
      throw error;
    });
  }
  return initPromise;
}
