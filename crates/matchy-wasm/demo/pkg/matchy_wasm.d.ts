/* tslint:disable */
/* eslint-disable */

export class Database {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Look up a string against patterns only
   *
   * Skips IP address parsing and only checks against glob patterns.
   *
   * @param text - String to match against patterns
   * @returns The associated data as a JavaScript object, or null if not found
   */
  lookupPattern(text: string): any;
  /**
   * Create a new Database from raw bytes (Uint8Array)
   *
   * @param bytes - Database file contents as Uint8Array
   * @throws Error if the database format is invalid
   */
  constructor(bytes: Uint8Array);
  /**
   * Get database query statistics
   *
   * @returns Object with query statistics (total_queries, cache_hits, etc.)
   */
  stats(): any;
  /**
   * Look up a key in the database
   *
   * Automatically detects whether the key is an IP address or pattern and
   * performs the appropriate lookup.
   *
   * @param key - IP address (e.g., "1.2.3.4") or string to match patterns
   * @returns The associated data as a JavaScript object, or null if not found
   */
  lookup(key: string): any;
  /**
   * Look up an IP address specifically
   *
   * Use this when you know the input is an IP address for slightly better performance.
   *
   * @param ip - IPv4 or IPv6 address string
   * @returns The associated data as a JavaScript object, or null if not found
   */
  lookupIp(ip: string): any;
}

export class DatabaseBuilder {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Add a literal string explicitly
   *
   * @param literal - Exact string to match
   * @param data - Associated data as a JavaScript object
   */
  addLiteral(literal: string, data: any): void;
  /**
   * Add a glob pattern explicitly
   *
   * @param pattern - Glob pattern (e.g., "*.evil.com", "malware-*")
   * @param data - Associated data as a JavaScript object
   */
  addPattern(pattern: string, data: any): void;
  /**
   * Create a new DatabaseBuilder
   *
   * @param case_sensitive - Whether pattern matching should be case-sensitive
   */
  constructor(case_sensitive: boolean);
  /**
   * Build the database and return as bytes
   *
   * @returns Uint8Array containing the database that can be saved or loaded
   */
  build(): Uint8Array;
  /**
   * Add an IP address or CIDR explicitly
   *
   * @param ip - IPv4/IPv6 address or CIDR (e.g., "1.2.3.4", "192.168.0.0/16")
   * @param data - Associated data as a JavaScript object
   */
  addIp(ip: string, data: any): void;
  /**
   * Add an entry (auto-detects IP vs pattern)
   *
   * The key is automatically classified:
   * - IP addresses (1.2.3.4, 192.168.0.0/16, ::1) go to IP tree
   * - Patterns with wildcards (*.example.com) go to pattern matcher
   * - Plain strings go to literal hash table
   *
   * @param key - IP address, CIDR, pattern, or literal string
   * @param data - Associated data as a JavaScript object
   */
  addEntry(key: string, data: any): void;
}

export class Extractor {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Extract entities from text
   *
   * Only extracts entity types that were enabled when building this extractor.
   *
   * @param text - Input text to search
   * @returns Array of extracted entities with type, value, start, and end
   */
  extract(text: string): any;
}

export class ExtractorBuilder {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Enable or disable IPv4 extraction
   */
  extractIpv4(enable: boolean): ExtractorBuilder;
  /**
   * Enable or disable IPv6 extraction
   */
  extractIpv6(enable: boolean): ExtractorBuilder;
  /**
   * Enable or disable email extraction
   */
  extractEmails(enable: boolean): ExtractorBuilder;
  /**
   * Enable or disable hash extraction (MD5, SHA1, SHA256, SHA384, SHA512)
   */
  extractHashes(enable: boolean): ExtractorBuilder;
  /**
   * Enable or disable Monero address extraction
   */
  extractMonero(enable: boolean): ExtractorBuilder;
  /**
   * Enable or disable Bitcoin address extraction
   */
  extractBitcoin(enable: boolean): ExtractorBuilder;
  /**
   * Enable or disable domain extraction
   */
  extractDomains(enable: boolean): ExtractorBuilder;
  /**
   * Enable or disable Ethereum address extraction
   */
  extractEthereum(enable: boolean): ExtractorBuilder;
  /**
   * Set minimum number of domain labels (default: 2 for "example.com")
   */
  minDomainLabels(min: number): ExtractorBuilder;
  /**
   * Create a new ExtractorBuilder with all extractors enabled by default
   */
  constructor();
  /**
   * Build the configured Extractor
   */
  build(): Extractor;
}

/**
 * Initialize the WASM module with better panic messages
 */
export function init(): void;

/**
 * Get the matchy library version
 */
export function version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_database_free: (a: number, b: number) => void;
  readonly __wbg_databasebuilder_free: (a: number, b: number) => void;
  readonly __wbg_extractor_free: (a: number, b: number) => void;
  readonly __wbg_extractorbuilder_free: (a: number, b: number) => void;
  readonly database_lookup: (a: number, b: number, c: number) => [number, number, number];
  readonly database_lookupIp: (a: number, b: number, c: number) => [number, number, number];
  readonly database_lookupPattern: (a: number, b: number, c: number) => [number, number, number];
  readonly database_new: (a: number, b: number) => [number, number, number];
  readonly database_stats: (a: number) => [number, number, number];
  readonly databasebuilder_addEntry: (a: number, b: number, c: number, d: any) => [number, number];
  readonly databasebuilder_addIp: (a: number, b: number, c: number, d: any) => [number, number];
  readonly databasebuilder_addLiteral: (a: number, b: number, c: number, d: any) => [number, number];
  readonly databasebuilder_addPattern: (a: number, b: number, c: number, d: any) => [number, number];
  readonly databasebuilder_build: (a: number) => [number, number, number, number];
  readonly databasebuilder_new: (a: number) => number;
  readonly extractor_extract: (a: number, b: number, c: number) => [number, number, number];
  readonly extractorbuilder_build: (a: number) => [number, number, number];
  readonly extractorbuilder_extractBitcoin: (a: number, b: number) => number;
  readonly extractorbuilder_extractDomains: (a: number, b: number) => number;
  readonly extractorbuilder_extractEmails: (a: number, b: number) => number;
  readonly extractorbuilder_extractEthereum: (a: number, b: number) => number;
  readonly extractorbuilder_extractHashes: (a: number, b: number) => number;
  readonly extractorbuilder_extractIpv4: (a: number, b: number) => number;
  readonly extractorbuilder_extractIpv6: (a: number, b: number) => number;
  readonly extractorbuilder_extractMonero: (a: number, b: number) => number;
  readonly extractorbuilder_minDomainLabels: (a: number, b: number) => number;
  readonly extractorbuilder_new: () => number;
  readonly version: () => [number, number];
  readonly init: () => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
