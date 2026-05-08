import { useState } from 'react';
import App from './App';
import './landing.css';

export default function Welcome() {
  const [open, setOpen] = useState(new URLSearchParams(window.location.search).has('dashboard'));
  const openDashboard = () => { window.history.pushState({}, '', '?dashboard'); setOpen(true); };
  if (open) return <App />;
  return <main className="welcome">
    <nav className="welcome-nav" aria-label="Main navigation"><a className="landing-brand" href="/"><span className="landing-mark">B</span>BoundaryLab</a><div className="landing-navlinks"><a href="#capabilities">Capabilities</a><a href="#how-it-works">How it works</a></div><button onClick={openDashboard}>Open dashboard <span aria-hidden="true">→</span></button></nav>
    <section className="welcome-hero"><div className="welcome-copy"><h1>Know what your agents are allowed to do.</h1><p>Inspect tool calls, test security policies, and trace decisions in one workspace.</p><div className="welcome-actions"><button onClick={openDashboard}>Open dashboard <span aria-hidden="true">→</span></button><a href="#how-it-works">How it works</a></div></div><figure className="welcome-preview"><img src="/dashboard-preview.png" width="1600" height="1000" alt="BoundaryLab dashboard displaying simulated policy decisions"/><figcaption>BoundaryLab dashboard with simulated activity</figcaption></figure></section>
    <section className="landing-intro" id="capabilities"><div><h2>See the decision behind every action.</h2><p>Agent requests move quickly. BoundaryLab gives developers a place to inspect the policies and security context around them.</p></div><div className="landing-list"><article><span>01</span><div><h3>Inspect activity</h3><p>Follow tool calls and investigate the policy behind each decision.</p></div></article><article><span>02</span><div><h3>Understand permissions</h3><p>Explore sessions, security labels, and how context changes access.</p></div></article><article><span>03</span><div><h3>Test a policy</h3><p>Evaluate example requests and explore a simulated scenario.</p></div></article></div></section>
    <section className="landing-graph" id="how-it-works"><div><h2>Follow the path from request to decision.</h2><p>See how tool calls move through classification, policy evaluation, and audit. Select events in the dashboard to inspect their details.</p><button onClick={openDashboard}>Open dashboard <span aria-hidden="true">→</span></button></div><figure><img src="/governance-preview.png" width="1600" height="1000" loading="lazy" alt="Governance graph showing the agent evaluation pipeline"/><figcaption>Governance graph from the simulated demo</figcaption></figure></section>
    <footer><a className="landing-brand" href="/">BoundaryLab</a><span>AI agent security and permissions laboratory</span></footer>
  </main>;
}
