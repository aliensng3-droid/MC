import { useState } from "react";

const opportunities = [
  {
    id: 1,
    segment: "AI-Powered Vertical SaaS",
    trendScore: 97,
    marketSize: "$48B",
    cagr: "34%",
    competition: "Medium",
    timeToRevenue: "6–12 mo",
    entryBarrier: "Low–Med",
    color: "#00FFB2",
    tags: ["AI/ML", "Industry-specific", "High retention"],
    insight: "Vertical SaaS with embedded AI commands 3–5× higher NPS and lower churn than horizontal tools. Healthcare, legal, and construction are underserved.",
    signals: ["Salesforce acquiring vertical AI cos", "85% of Fortune 500 have vertical SaaS budgets", "GPT-4o API costs dropped 80% in 18 months"],
    risks: ["Distribution moat needed", "Deep domain expertise required"],
    playbook: "Pick one painful workflow in a regulated industry → embed AI → land & expand via team seats.",
  },
  {
    id: 2,
    segment: "Workflow Automation for SMBs",
    trendScore: 88,
    marketSize: "$26B",
    cagr: "27%",
    competition: "High",
    timeToRevenue: "3–6 mo",
    entryBarrier: "Low",
    color: "#FFD166",
    tags: ["SMB", "No-code", "Fast sales cycle"],
    insight: "Zapier & Make dominate but leave huge gaps for industry-specific automation. SMBs pay $50–500/mo and churn slowly if core ops depend on the tool.",
    signals: ["55M SMBs in the US alone", "Average SMB uses 9 SaaS tools", "No-code market grew 45% YoY"],
    risks: ["Zapier can clone features", "Price sensitivity at SMB tier"],
    playbook: "Identify a 5-step manual process in a niche (e.g., HVAC dispatch) → automate end-to-end → charge per outcome.",
  },
  {
    id: 3,
    segment: "B2B Developer Tools",
    trendScore: 82,
    marketSize: "$32B",
    cagr: "22%",
    competition: "Very High",
    timeToRevenue: "9–18 mo",
    entryBarrier: "High",
    color: "#A78BFA",
    tags: ["PLG", "Bottom-up", "Sticky"],
    insight: "PLG (product-led growth) dev tools with usage-based pricing win big. Observability, security, and AI infra remain greenfield despite crowding.",
    signals: ["GitHub hit 100M developers", "Security spend up 41% post-breach wave", "AI infra layer is still raw"],
    risks: ["Long trust-building cycle", "Open source can undercut pricing"],
    playbook: "Build a free tier that solves one acute dev pain → viral word-of-mouth → upsell teams/orgs on collaboration.",
  },
  {
    id: 4,
    segment: "Compliance & RegTech SaaS",
    trendScore: 79,
    marketSize: "$19B",
    cagr: "19%",
    competition: "Low–Med",
    timeToRevenue: "9–15 mo",
    entryBarrier: "Med–High",
    color: "#F97316",
    tags: ["Regulatory moat", "Enterprise", "Recurring pain"],
    insight: "New regulations (AI Act, SEC climate rules, state privacy laws) create mandatory spend. Early movers lock in long contracts — compliance tools rarely get ripped out.",
    signals: ["EU AI Act effective 2025", "SEC climate disclosure rules finalized", "HIPAA violation fines up 300%"],
    risks: ["Slow enterprise sales cycles", "Regulation can be delayed or repealed"],
    playbook: "Map a pending regulation → build a compliance dashboard before the deadline hits → sell urgency.",
  },
  {
    id: 5,
    segment: "Micro-SaaS / Niche Tools",
    trendScore: 74,
    marketSize: "$4B",
    cagr: "31%",
    competition: "Low",
    timeToRevenue: "1–3 mo",
    entryBarrier: "Very Low",
    color: "#38BDF8",
    tags: ["Solo-friendly", "Low overhead", "Fast validation"],
    insight: "Sub-$50/mo tools solving one specific problem for a defined audience. Fastest path to $10K MRR. Acqui-hire or acquisition at 3–5× ARR is common exit.",
    signals: ["Micro-SaaS communities growing 200% YoY", "Acquire.com listings up 4×", "Solo founders hitting $1M ARR"],
    risks: ["Hard to scale beyond $1–2M ARR", "Large players can bundle your feature"],
    playbook: "Find a Reddit/forum complaint repeated 10+ times → build an MVP in a weekend → charge $29/mo on day 1.",
  },
];

const frameworkSteps = [
  { step: "01", label: "Identify the Pain", desc: "Talk to 20 potential customers before writing a line of code. Look for problems people are already paying to solve badly." },
  { step: "02", label: "Size the Market", desc: "Bottom-up: # of buyers × willingness to pay. You need a market large enough to reach $10M ARR, not necessarily $1B TAM." },
  { step: "03", label: "Map the Competition", desc: "Incumbents = proof of demand. Find their 1-star reviews — that's your roadmap. Differentiate on UX, price, or vertical focus." },
  { step: "04", label: "Pick Your GTM", desc: "PLG for dev tools, direct sales for enterprise, SEO for SMBs. Your go-to-market should match your buyer's purchase behavior." },
  { step: "05", label: "Validate Fast", desc: "Charge before you build. A Stripe payment link and a Typeform beats 6 months of development. Aim for 3 paying customers in 30 days." },
  { step: "06", label: "Choose Your Metric", desc: "Pick one north-star: MRR, DAU, or NPS. Startups that optimize one metric early grow 2× faster than those chasing vanity metrics." },
];

const competitionColor = { "Low": "#00FFB2", "Low–Med": "#A3E635", "Medium": "#FFD166", "Med–High": "#FB923C", "High": "#F87171", "Very High": "#EF4444" };

export default function App() {
  const [selected, setSelected] = useState(null);
  const [tab, setTab] = useState("opportunities");
  const [hovered, setHovered] = useState(null);

  const opp = opportunities.find(o => o.id === selected);

  return (
    <div style={{
      fontFamily: "'DM Mono', 'Courier New', monospace",
      background: "#0A0A0F",
      minHeight: "100vh",
      color: "#E2E8F0",
      padding: "0",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@700;800&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #0A0A0F; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 2px; }
        .card { transition: all 0.2s ease; cursor: pointer; }
        .card:hover { transform: translateY(-2px); }
        .tab-btn { transition: all 0.2s ease; }
        .tag { font-size: 10px; padding: 2px 8px; border-radius: 999px; font-family: 'DM Mono', monospace; letter-spacing: 0.05em; }
        .bar-fill { transition: width 0.8s cubic-bezier(.22,1,.36,1); }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        .fade-in { animation: fadeIn 0.35s ease forwards; }
        @keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:0.5 } }
        .pulse { animation: pulse 2s infinite; }
      `}</style>

      {/* Header */}
      <div style={{ borderBottom: "1px solid #1E1E2E", padding: "28px 40px 20px", display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <div style={{ fontSize: 11, letterSpacing: "0.2em", color: "#4B5563", marginBottom: 6, textTransform: "uppercase" }}>SaaS Startup Intelligence</div>
          <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 28, fontWeight: 800, letterSpacing: "-0.02em", lineHeight: 1 }}>
            Market <span style={{ color: "#00FFB2" }}>Opportunity</span> Scanner
          </div>
        </div>
        <div style={{ textAlign: "right", fontSize: 11, color: "#4B5563", letterSpacing: "0.05em" }}>
          <div>UPDATED</div>
          <div style={{ color: "#00FFB2" }}>Q1 2026</div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ padding: "0 40px", borderBottom: "1px solid #1E1E2E", display: "flex", gap: 0 }}>
        {[["opportunities", "Market Segments"], ["framework", "Launch Framework"]].map(([key, label]) => (
          <button key={key} className="tab-btn" onClick={() => { setTab(key); setSelected(null); }} style={{
            background: "none", border: "none", color: tab === key ? "#00FFB2" : "#4B5563",
            padding: "14px 0", marginRight: 32, cursor: "pointer",
            borderBottom: tab === key ? "2px solid #00FFB2" : "2px solid transparent",
            fontSize: 12, letterSpacing: "0.1em", textTransform: "uppercase", fontFamily: "'DM Mono', monospace",
            fontWeight: tab === key ? 500 : 400,
          }}>{label}</button>
        ))}
      </div>

      {tab === "opportunities" && (
        <div style={{ display: "grid", gridTemplateColumns: selected ? "1fr 1fr" : "1fr", gap: 0, minHeight: "calc(100vh - 140px)" }}>
          {/* Segment List */}
          <div style={{ padding: "24px 40px", borderRight: selected ? "1px solid #1E1E2E" : "none" }}>
            <div style={{ fontSize: 11, color: "#4B5563", letterSpacing: "0.15em", marginBottom: 16, textTransform: "uppercase" }}>
              {selected ? "← Click another to compare" : "Select a segment to explore"}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {opportunities.map(o => (
                <div key={o.id} className="card" onClick={() => setSelected(selected === o.id ? null : o.id)}
                  style={{
                    background: selected === o.id ? "#0F0F1A" : "#0D0D15",
                    border: `1px solid ${selected === o.id ? o.color : "#1E1E2E"}`,
                    borderRadius: 10, padding: "16px 20px",
                    boxShadow: selected === o.id ? `0 0 20px ${o.color}22` : "none",
                  }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 500, marginBottom: 4, fontFamily: "'Syne', sans-serif" }}>{o.segment}</div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        {o.tags.map(t => (
                          <span key={t} className="tag" style={{ background: `${o.color}18`, color: o.color, border: `1px solid ${o.color}44` }}>{t}</span>
                        ))}
                      </div>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontSize: 22, fontFamily: "'Syne', sans-serif", fontWeight: 800, color: o.color }}>{o.trendScore}</div>
                      <div style={{ fontSize: 9, color: "#4B5563", letterSpacing: "0.1em" }}>SCORE</div>
                    </div>
                  </div>
                  {/* Mini bar */}
                  <div style={{ display: "flex", gap: 16, fontSize: 11, color: "#6B7280" }}>
                    <span>Market: <span style={{ color: "#E2E8F0" }}>{o.marketSize}</span></span>
                    <span>CAGR: <span style={{ color: "#E2E8F0" }}>{o.cagr}</span></span>
                    <span>Competition: <span style={{ color: competitionColor[o.competition] || "#E2E8F0" }}>{o.competition}</span></span>
                  </div>
                  {/* Trend bar */}
                  <div style={{ marginTop: 10, height: 3, background: "#1E1E2E", borderRadius: 2, overflow: "hidden" }}>
                    <div className="bar-fill" style={{ height: "100%", width: `${o.trendScore}%`, background: `linear-gradient(90deg, ${o.color}88, ${o.color})`, borderRadius: 2 }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Detail Panel */}
          {opp && (
            <div className="fade-in" style={{ padding: "24px 36px", overflowY: "auto" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
                <div>
                  <div style={{ fontSize: 10, color: "#4B5563", letterSpacing: "0.2em", textTransform: "uppercase", marginBottom: 6 }}>Deep Dive</div>
                  <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 20, fontWeight: 800, color: opp.color }}>{opp.segment}</div>
                </div>
                <button onClick={() => setSelected(null)} style={{ background: "none", border: "1px solid #1E1E2E", color: "#4B5563", borderRadius: 6, padding: "4px 12px", cursor: "pointer", fontSize: 11, fontFamily: "'DM Mono', monospace" }}>✕ Close</button>
              </div>

              {/* Stats Grid */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 20 }}>
                {[
                  ["Market Size", opp.marketSize], ["CAGR", opp.cagr],
                  ["Time to Revenue", opp.timeToRevenue], ["Entry Barrier", opp.entryBarrier],
                ].map(([label, val]) => (
                  <div key={label} style={{ background: "#0D0D15", border: "1px solid #1E1E2E", borderRadius: 8, padding: "12px 16px" }}>
                    <div style={{ fontSize: 10, color: "#4B5563", letterSpacing: "0.1em", marginBottom: 4, textTransform: "uppercase" }}>{label}</div>
                    <div style={{ fontSize: 18, fontFamily: "'Syne', sans-serif", fontWeight: 700 }}>{val}</div>
                  </div>
                ))}
              </div>

              {/* Insight */}
              <div style={{ background: `${opp.color}0D`, border: `1px solid ${opp.color}33`, borderRadius: 8, padding: "14px 16px", marginBottom: 16 }}>
                <div style={{ fontSize: 10, color: opp.color, letterSpacing: "0.15em", marginBottom: 6, textTransform: "uppercase" }}>Key Insight</div>
                <div style={{ fontSize: 13, lineHeight: 1.6, color: "#CBD5E1" }}>{opp.insight}</div>
              </div>

              {/* Market Signals */}
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 10, color: "#4B5563", letterSpacing: "0.15em", marginBottom: 10, textTransform: "uppercase" }}>Market Signals</div>
                {opp.signals.map((s, i) => (
                  <div key={i} style={{ display: "flex", gap: 10, marginBottom: 8, alignItems: "flex-start" }}>
                    <span className="pulse" style={{ color: opp.color, fontSize: 8, marginTop: 4 }}>●</span>
                    <span style={{ fontSize: 12, color: "#94A3B8", lineHeight: 1.5 }}>{s}</span>
                  </div>
                ))}
              </div>

              {/* Risks */}
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 10, color: "#4B5563", letterSpacing: "0.15em", marginBottom: 10, textTransform: "uppercase" }}>Watch Out For</div>
                {opp.risks.map((r, i) => (
                  <div key={i} style={{ display: "flex", gap: 10, marginBottom: 8, alignItems: "flex-start" }}>
                    <span style={{ color: "#F87171", fontSize: 10, marginTop: 2 }}>▲</span>
                    <span style={{ fontSize: 12, color: "#94A3B8", lineHeight: 1.5 }}>{r}</span>
                  </div>
                ))}
              </div>

              {/* Playbook */}
              <div style={{ background: "#0D0D15", border: "1px solid #1E1E2E", borderRadius: 8, padding: "14px 16px" }}>
                <div style={{ fontSize: 10, color: "#4B5563", letterSpacing: "0.15em", marginBottom: 8, textTransform: "uppercase" }}>Starter Playbook</div>
                <div style={{ fontSize: 13, color: "#E2E8F0", lineHeight: 1.7 }}>{opp.playbook}</div>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === "framework" && (
        <div className="fade-in" style={{ padding: "32px 40px" }}>
          <div style={{ fontSize: 11, color: "#4B5563", letterSpacing: "0.15em", marginBottom: 24, textTransform: "uppercase" }}>
            SaaS Startup Launch — 6-Step Framework
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 16 }}>
            {frameworkSteps.map((s, i) => (
              <div key={i} style={{ background: "#0D0D15", border: "1px solid #1E1E2E", borderRadius: 10, padding: "20px 22px", position: "relative", overflow: "hidden" }}>
                <div style={{ position: "absolute", top: 16, right: 18, fontFamily: "'Syne', sans-serif", fontSize: 40, fontWeight: 800, color: "#ffffff08" }}>{s.step}</div>
                <div style={{ fontSize: 11, color: "#00FFB2", letterSpacing: "0.2em", marginBottom: 8 }}>{s.step}</div>
                <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: 16, marginBottom: 10 }}>{s.label}</div>
                <div style={{ fontSize: 12, color: "#94A3B8", lineHeight: 1.7 }}>{s.desc}</div>
              </div>
            ))}
          </div>

          {/* Bottom CTA */}
          <div style={{ marginTop: 32, background: "#0D0D15", border: "1px solid #1E1E2E", borderRadius: 10, padding: "20px 24px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
            <div>
              <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: 15, marginBottom: 4 }}>Ready to go deeper?</div>
              <div style={{ fontSize: 12, color: "#6B7280" }}>Tell me your specific idea and I'll give you a tailored competitive and GTM analysis.</div>
            </div>
            <div style={{ fontSize: 11, color: "#00FFB2", letterSpacing: "0.1em", border: "1px solid #00FFB244", padding: "8px 16px", borderRadius: 6 }}>
              → Share your idea in chat
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
