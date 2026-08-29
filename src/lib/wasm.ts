'use client';

import { useEffect, useState } from 'react';
import init, * as wasm from '../../public/pkg/wasm_crypto';

export type WasmModule = typeof wasm;
export { wasm };

let pending: Promise<void> | null = null;

/** Instantiates the WebAssembly module once per page load. */
export function loadWasm(): Promise<void> {
  if (!pending) {
    pending = init({ module_or_path: '/pkg/wasm_crypto_bg.wasm' }).then(() => undefined);
  }
  return pending;
}

export type WasmState = 'loading' | 'ready' | 'error';

/** Tracks module readiness; controls should be disabled until 'ready'. */
export function useWasm(): WasmState {
  const [state, setState] = useState<WasmState>('loading');
  useEffect(() => {
    let alive = true;
    loadWasm().then(
      () => { if (alive) setState('ready'); },
      (err: unknown) => { console.error(err); if (alive) setState('error'); },
    );
    return () => { alive = false; };
  }, []);
  return state;
}

export type Attempt<T> = { ok: true; value: T } | { ok: false; error: string };

/** Runs a wasm call and converts a thrown JsError into a value. */
export function attempt<T>(fn: () => T): Attempt<T> {
  try {
    return { ok: true, value: fn() };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
