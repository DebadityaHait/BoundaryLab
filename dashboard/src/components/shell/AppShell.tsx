import React, { useState } from 'react';

interface AppShellProps {
  header: React.ReactNode;
  metricsBar: React.ReactNode;
  sidebar: React.ReactNode;
  main: React.ReactNode;
  inspector: React.ReactNode;
}

export function AppShell({ header, metricsBar, sidebar, main, inspector }: AppShellProps) {
  const [panel, setPanel] = useState<'activity' | 'policies' | 'inspector'>('activity');
  return <div className="workspace">
    <header className="workspace-header" aria-label="Connection and policy summary">{header}</header>
    <div className="workspace-title"><h1>Agent activity</h1><p>Monitor policy decisions and investigate agent behavior.</p></div>
    <div role="status" aria-label="Dashboard metrics" className="workspace-metrics">{metricsBar}</div>
    <nav className="workspace-mobile-nav" aria-label="Workspace panels">{(['activity', 'policies', 'inspector'] as const).map(item => <button key={item} onClick={() => setPanel(item)} aria-pressed={panel === item}>{item}</button>)}</nav>
    <div className="workspace-grid" data-panel={panel}>
      <aside className="workspace-sidebar">{sidebar}</aside><main className="workspace-main" aria-label="Live event stream">{main}</main><aside className="workspace-inspector" aria-label="Inspector panel">{inspector}</aside>
    </div>
  </div>;
}
interface AppHeaderProps { connectionState: string; onStartDemo: () => void; onStopDemo: () => void; onOpenPalette: () => void; onOpenPlayground: () => void; }
export function AppHeader({ connectionState, onStartDemo, onStopDemo, onOpenPalette, onOpenPlayground }: AppHeaderProps) {
 const isMock = connectionState === 'MOCK';
 return <div className="workspace-header-inner"><a className="workspace-brand" href="/"><span className="brand-mark">B</span>BoundaryLab</a><span className="connection-status" data-state={connectionState}><span className="connection-dot" />{isMock ? 'Demo mode' : connectionState.toLowerCase()}</span><div className="workspace-actions"><button className="workspace-action workspace-command" onClick={onOpenPalette}>Commands <kbd>Ctrl K</kbd></button><button className="workspace-action" onClick={onOpenPlayground}>Evaluate policy</button><button className="workspace-action primary" onClick={isMock ? onStopDemo : onStartDemo}>{isMock ? 'Stop demo' : 'Start demo'}</button></div></div>;
}

interface MetricProps {
  eventsPerSec: number;
  denyRate: number;
  p99LatencyMs: number;
  bufferPct: number;
  coalescedCount: number;
}

export function AppMetricsBar({ eventsPerSec, denyRate, p99LatencyMs, bufferPct, coalescedCount }: MetricProps) {
  const denyColor = denyRate > 10 ? 'var(--deny)' : denyRate > 5 ? 'var(--escalate)' : 'var(--text-secondary)';
  return (
    <div style={{
      display: 'flex', alignItems: 'center', height: '100%',
      padding: '0 16px', gap: 20,
      fontSize: 11, color: 'var(--text-secondary)',
    }}>
      <Metric label="EVENTS/S"   value={eventsPerSec.toFixed(1)} />
      <Metric label="DENY"       value={`${denyRate.toFixed(1)}%`} valueColor={denyColor} />
      <Metric label="P99"        value={`${p99LatencyMs.toFixed(2)}ms`} />
      <Metric label="BUFFER"     value={`${bufferPct.toFixed(0)}%`} />
      {coalescedCount > 0 && (
        <Metric label="COALESCED" value={`${coalescedCount}`} valueColor="var(--text-muted)" />
      )}
    </div>
  );
}

function Metric({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
      <span style={{ textTransform: 'uppercase', letterSpacing: '0.06em', fontSize: 10 }}>{label}</span>
      <span style={{ color: valueColor ?? 'var(--text-primary)', fontVariantNumeric: 'tabular-nums', fontWeight: 500 }}>
        {value}
      </span>
    </div>
  );
}
