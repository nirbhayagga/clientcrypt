'use client';

import { useId, useState, type ReactNode, type ComponentProps } from 'react';

/* Page scaffold ------------------------------------------------------------ */

export function Page({ kicker, title, lede, children }: { kicker: string; title: string; lede?: ReactNode; children: ReactNode }) {
  return (
    <>
      <header className="page-head">
        <div className="kicker">{kicker}</div>
        <h1>{title}</h1>
        {lede && <p className="lede">{lede}</p>}
      </header>
      <div className="stack">{children}</div>
    </>
  );
}

export function Panel({ title, refs, action, children, className }: { title?: ReactNode; refs?: string[]; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className ?? ''}`}>
      {(title || refs || action) && (
        <div className="panel-head">
          {title && <h2>{title}</h2>}
          <div className="row">
            {refs && <div className="refs">{refs.map((r) => <span key={r} className="tag">{r}</span>)}</div>}
            {action}
          </div>
        </div>
      )}
      {children}
    </section>
  );
}

export function Note({ title = 'Note', children }: { title?: string; children: ReactNode }) {
  return (
    <aside className="note">
      <div className="note-title">{title}</div>
      {children}
    </aside>
  );
}

export function Callout({ tone, children }: { tone: 'ok' | 'danger' | 'warn' | 'info'; children: ReactNode }) {
  return <div className={`callout callout-${tone}`} role="status">{children}</div>;
}

export function Tag({ tone, children }: { tone?: 'accent' | 'ok' | 'danger'; children: ReactNode }) {
  return <span className={`tag ${tone ? `tag-${tone}` : ''}`}>{children}</span>;
}

/* Forms -------------------------------------------------------------------- */

export function Field({ label, hint, children, id }: { label: ReactNode; hint?: ReactNode; children: (id: string) => ReactNode; id?: string }) {
  const auto = useId();
  const fid = id ?? auto;
  return (
    <div className="field">
      <label className="label" htmlFor={fid}>
        <span>{label}</span>
        {hint && <span className="hint">{hint}</span>}
      </label>
      {children(fid)}
    </div>
  );
}

type InputProps = ComponentProps<'input'> & { mono?: boolean; invalid?: boolean };
export function TextInput({ mono, invalid, className, ...rest }: InputProps) {
  return <input type="text" spellCheck={false} autoComplete="off" className={`input ${mono ? 'mono' : ''} ${invalid ? 'invalid' : ''} ${className ?? ''}`} {...rest} />;
}

type TextAreaProps = ComponentProps<'textarea'> & { mono?: boolean; invalid?: boolean };
export function TextArea({ mono, invalid, className, ...rest }: TextAreaProps) {
  return <textarea spellCheck={false} className={`textarea ${mono ? 'mono' : ''} ${invalid ? 'invalid' : ''} ${className ?? ''}`} {...rest} />;
}

export function Select({ className, ...rest }: ComponentProps<'select'>) {
  return <select className={`select ${className ?? ''}`} {...rest} />;
}

type ButtonProps = ComponentProps<'button'> & { variant?: 'primary' | 'ghost' | 'default'; size?: 'sm'; block?: boolean };
export function Button({ variant = 'default', size, block, className, type = 'button', ...rest }: ButtonProps) {
  const cls = ['btn', variant !== 'default' && `btn-${variant}`, size && `btn-${size}`, block && 'btn-block', className].filter(Boolean).join(' ');
  return <button type={type} className={cls} {...rest} />;
}

export function Segmented<T extends string>({ options, value, onChange, label, disabled }: { options: { value: T; label: string }[]; value: T; onChange: (v: T) => void; label: string; disabled?: boolean }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={value === o.value} onClick={() => onChange(o.value)} disabled={disabled}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Range({ label, value, min, max, step, onChange, format, disabled }: { label: string; value: number; min: number; max: number; step?: number; onChange: (v: number) => void; format?: (v: number) => string; disabled?: boolean }) {
  const id = useId();
  return (
    <div className="field">
      <label className="label" htmlFor={id}>
        <span>{label}</span>
        <span className="hint mono">{format ? format(value) : value}</span>
      </label>
      <input id={id} type="range" min={min} max={max} step={step ?? 1} value={value} onChange={(e) => onChange(Number(e.target.value))} disabled={disabled} />
    </div>
  );
}

/* Output ------------------------------------------------------------------- */

export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      size="sm" variant="ghost" className="copy"
      aria-label="Copy to clipboard"
      disabled={!text}
      onClick={async () => {
        try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1200); } catch { /* clipboard unavailable */ }
      }}
    >
      {done ? 'copied' : 'copy'}
    </Button>
  );
}

export function Output({ label, value, tone, copy = true, scroll, placeholder = '—', ariaLabel }: { label?: ReactNode; value: string; tone?: 'ok' | 'danger' | 'accent' | 'muted'; copy?: boolean; scroll?: boolean; placeholder?: string; ariaLabel?: string }) {
  const empty = value.length === 0;
  return (
    <div className="out-wrap">
      {label && <div className="label"><span>{label}</span></div>}
      <pre className={`out ${tone ? `tone-${tone}` : ''} ${empty ? 'tone-muted' : ''} ${copy ? 'has-copy' : ''} ${scroll ? 'out-scroll' : ''}`} aria-label={ariaLabel}>
        {empty ? placeholder : value}
        {copy && !empty && <CopyButton text={value} />}
      </pre>
    </div>
  );
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: 'ok' | 'warn' | 'danger' | 'accent' | 'info' }) {
  return (
    <div className={`stat ${tone ? `tone-${tone}` : ''}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export function Status({ state, error }: { state: 'loading' | 'ready' | 'error'; error?: string }) {
  if (state === 'ready') return null;
  return (
    <p className={`status ${state === 'error' ? 'error' : ''}`} role="status">
      {state === 'loading' ? 'Loading WebAssembly module…' : `WebAssembly module failed to load${error ? `: ${error}` : ''}.`}
    </p>
  );
}

export function ErrorText({ error }: { error?: string | null }) {
  if (!error) return null;
  return <p className="status error" role="alert">{error}</p>;
}
