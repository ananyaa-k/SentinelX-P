import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Shield } from 'lucide-react';
import { useScanContext } from '../context/ScanContext';
import ThreatChip from '../components/ThreatChip';

const Dashboard: React.FC = () => {
  const { scans } = useScanContext();

  const stats = [
    { value: '1000', label: 'EMBER SAMPLES', borderColor: 'border-l-coral' },
    { value: '94.33%', label: 'DETECTION ACCURACY', borderColor: 'border-l-mint' },
    { value: '4.52%', label: 'FALSE NEGATIVE RATE', borderColor: 'border-l-mint' },
    { value: '10', label: 'MALWARE FAMILIES', borderColor: 'border-l-gold' },
  ];

  const howItWorks = [
    { step: '01', title: 'UPLOAD', desc: 'Drop a PE binary. YARA scans for known signatures instantly.', borderColor: 'border-l-coral' },
    { step: '02', title: 'ANALYZE', desc: 'AI heuristic layer detects evasive/packed malware YARA misses.', borderColor: 'border-l-gold' },
    { step: '03', title: 'REPORT', desc: 'Auto-generated YARA rule + threat report downloaded instantly.', borderColor: 'border-l-mint' },
  ];

  const recentScans = scans.slice(0, 5);

  return (
    <div className="min-h-screen pt-14 mosaic-bg" data-testid="dashboard-page">
      <div className="max-w-[1400px] mx-auto px-6 py-16">
        {/* Hero Section */}
        <section className="mb-20">
          <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-4">
            — CYBER THREAT INTELLIGENCE PLATFORM
          </p>
          <h1 className="font-heading text-6xl md:text-7xl font-bold text-[#1A3C2B] tracking-tight mb-6">
            SENTINEL<span className="text-[#FF8C69]">X</span> DEFENDER
          </h1>
          <p className="text-lg text-[#1A1A18] max-w-2xl mb-10 leading-relaxed">
            Hybrid malware detection combining YARA static signatures with Generative AI heuristics 
            for automated zero-day defense.
          </p>
          <div className="flex flex-wrap gap-4">
            <Link
              to="/scanner"
              className="inline-flex items-center gap-2 px-6 py-3 bg-[#1A3C2B] text-white font-heading font-semibold text-sm uppercase tracking-wide hover:bg-[#2C4E3D] transition-colors"
              data-testid="analyze-file-btn"
            >
              <ArrowRight className="w-4 h-4" />
              Analyze a File
            </Link>
            <Link
              to="/threats"
              className="inline-flex items-center gap-2 px-6 py-3 border border-[rgba(58,58,56,0.2)] text-[#1A3C2B] font-heading font-semibold text-sm uppercase tracking-wide hover:bg-[rgba(26,60,43,0.05)] transition-colors"
              data-testid="view-threats-btn"
            >
              View Threat Feed
            </Link>
          </div>
        </section>

        {/* Stats Row */}
        <section className="mb-16">
          <div className="bento-grid grid-cols-2 md:grid-cols-4">
            {stats.map((stat) => (
              <div key={stat.label} className={`bento-cell ${stat.borderColor}`}>
                <p className="font-heading text-5xl font-bold text-[#1A3C2B] mb-2">{stat.value}</p>
                <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68]">{stat.label}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Status Bar */}
        <section className="mb-16">
          <div className="inline-flex items-center gap-6 px-4 py-3 border border-[rgba(58,58,56,0.2)] bg-white">
            {[
              { label: 'YARA ENGINE', status: 'ONLINE' },
              { label: 'GBM MODEL', status: 'LOADED' },
              { label: 'LLM LAYER', status: 'ACTIVE' },
            ].map((item, i) => (
              <React.Fragment key={item.label}>
                <div className="flex items-center gap-2">
                  <div className="status-dot" />
                  <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68]">
                    {item.label}: <span className="text-[#1A3C2B]">{item.status}</span>
                  </span>
                </div>
                {i < 2 && <span className="text-[#6B6B68]">·</span>}
              </React.Fragment>
            ))}
          </div>
        </section>

        {/* How It Works */}
        <section className="mb-16">
          <h2 className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-6">HOW IT WORKS</h2>
          <div className="bento-grid grid-cols-1 md:grid-cols-3">
            {howItWorks.map((item) => (
              <div key={item.step} className={`bento-cell ${item.borderColor}`}>
                <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-3">{item.step} — {item.title}</p>
                <p className="text-[#1A1A18]">{item.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Recent Scans */}
        <section>
          <h2 className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-6">RECENT SCANS</h2>
          <div className="bg-white border border-[rgba(58,58,56,0.2)]">
            {recentScans.length > 0 ? (
              <table className="data-table" data-testid="recent-scans-table">
                <thead>
                  <tr>
                    <th>SCAN ID</th>
                    <th>FILE</th>
                    <th>THREAT</th>
                    <th>CONFIDENCE</th>
                    <th>TIME</th>
                  </tr>
                </thead>
                <tbody>
                  {recentScans.map((scan) => (
                    <tr key={scan.scan_id}>
                      <td className="font-mono text-[11px] text-[#6B6B68]">{scan.scan_id}</td>
                      <td className="text-[13px]">{scan.filename}</td>
                      <td><ThreatChip level={scan.threat_level} size="sm" /></td>
                      <td className="font-mono text-[11px]" style={{ color: scan.threat_level === 'MALICIOUS' ? '#FF8C69' : scan.threat_level === 'SUSPICIOUS' ? '#F4D35E' : '#1A3C2B' }}>
                        {(scan.confidence_score * 100).toFixed(1)}%
                      </td>
                      <td className="font-mono text-[10px] text-[#6B6B68]">{scan.ts}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="py-16 text-center">
                <Shield className="w-12 h-12 text-[rgba(26,60,43,0.2)] mx-auto mb-4" />
                <p className="text-[#6B6B68] mb-4">No scans yet — run your first analysis</p>
                <Link
                  to="/scanner"
                  className="inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-[0.1em] text-[#1A3C2B] hover:underline"
                >
                  <ArrowRight className="w-3 h-3" />
                  Go to Scanner
                </Link>
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
};

export default Dashboard;
