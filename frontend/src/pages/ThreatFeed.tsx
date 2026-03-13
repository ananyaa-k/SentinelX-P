import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { Shield, ArrowRight, Activity } from 'lucide-react';
import { useScanContext } from '../context/ScanContext';
import ThreatChip from '../components/ThreatChip';
import {
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer,
  Cell, Tooltip, CartesianGrid,
} from 'recharts';

type FilterLevel = 'ALL' | 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE';

const PULSE_CSS = `
@keyframes fadeSlideIn {
  from { opacity: 0; transform: translateY(-6px); background-color: rgba(26,60,43,0.06); }
  to   { opacity: 1; transform: translateY(0);    background-color: transparent; }
}
.new-row { animation: fadeSlideIn 0.5s ease forwards; }
`;

const ThreatFeed: React.FC = () => {
  const { scans, isLive } = useScanContext() as any;
  const [filter, setFilter]       = useState<FilterLevel>('ALL');
  const [prevCount, setPrevCount] = useState(0);
  const [newIds, setNewIds]       = useState<Set<string>>(new Set());
  const [pulse, setPulse]         = useState(false);

  useEffect(() => {
    if (scans.length > prevCount && prevCount > 0) {
      const added = scans.slice(0, scans.length - prevCount).map((s: any) => s.scan_id);
      setNewIds(new Set(added));
      setPulse(true);
      setTimeout(() => { setNewIds(new Set()); setPulse(false); }, 2000);
    }
    setPrevCount(scans.length);
  }, [scans.length]); // eslint-disable-line

  const filtered = filter === 'ALL' ? scans : scans.filter((s: any) => s.threat_level === filter);
  const malCount  = scans.filter((s: any) => s.threat_level === 'MALICIOUS').length;
  const susCount  = scans.filter((s: any) => s.threat_level === 'SUSPICIOUS').length;
  const safeCount = scans.filter((s: any) => s.threat_level === 'SAFE').length;
  const total     = scans.length || 1;

  const chartData = scans.slice(0, 30).map((s: any, i: number) => ({
    i: i + 1,
    val: Math.round(s.confidence_score * 100),
    level: s.threat_level,
  }));

  const barColor = (l: string) =>
    l === 'MALICIOUS' ? '#FF8C69' : l === 'SUSPICIOUS' ? '#F4D35E' : '#9EFFBF';

  return (
    <div className="min-h-screen pt-14 mosaic-bg" data-testid="threats-page">
      <style>{PULSE_CSS}</style>
      <div className="max-w-[1400px] mx-auto px-6 py-12">

        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-2">
              03. LIVE DETECTION ACTIVITY
            </p>
            <h1 className="font-heading text-4xl font-bold text-[#1A3C2B]">THREAT FEED</h1>
          </div>
          <div className={`flex items-center gap-2 px-3 py-1.5 border font-mono text-[10px] uppercase tracking-[0.1em] ${
            isLive ? 'border-[#1A3C2B] text-[#1A3C2B]' : 'border-[rgba(58,58,56,0.2)] text-[#6B6B68]'
          }`}>
            <span className={`w-2 h-2 rounded-full ${isLive ? 'bg-[#9EFFBF]' : 'bg-[#6B6B68]'} ${pulse ? 'animate-ping' : isLive ? 'animate-pulse' : ''}`} />
            {isLive ? 'LIVE' : 'OFFLINE'}
          </div>
        </div>

        {/* Stats strip */}
        <div className="grid grid-cols-4 border border-[rgba(58,58,56,0.2)] mb-6 bg-white">
          {[
            { label: 'TOTAL SCANS', val: scans.length, color: '#1A3C2B' },
            { label: 'MALICIOUS',   val: malCount,     color: '#FF8C69' },
            { label: 'SUSPICIOUS',  val: susCount,     color: '#F4D35E' },
            { label: 'SAFE',        val: safeCount,    color: '#9EFFBF' },
          ].map((s, i) => (
            <div key={s.label} className={`px-6 py-4 ${i < 3 ? 'border-r border-[rgba(58,58,56,0.2)]' : ''}`}>
              <p className="font-mono text-[9px] uppercase tracking-[0.12em] text-[#6B6B68]">{s.label}</p>
              <p className="font-heading text-3xl font-bold mt-1 transition-all duration-300" style={{ color: s.color }}>{s.val}</p>
            </div>
          ))}
        </div>

        {/* Distribution bar */}
        {scans.length > 0 && (
          <div className="mb-6 bg-white border border-[rgba(58,58,56,0.2)] p-4">
            <p className="font-mono text-[9px] uppercase tracking-[0.12em] text-[#6B6B68] mb-3">THREAT DISTRIBUTION</p>
            <div className="flex h-2 w-full overflow-hidden gap-px">
              <div style={{ width: `${(malCount/total)*100}%`, background:'#FF8C69' }} className="transition-all duration-700" />
              <div style={{ width: `${(susCount/total)*100}%`, background:'#F4D35E' }} className="transition-all duration-700" />
              <div style={{ width: `${(safeCount/total)*100}%`, background:'#9EFFBF' }} className="transition-all duration-700" />
            </div>
            <div className="flex gap-6 mt-2">
              {[
                { color:'#FF8C69', label:'Malicious',  pct:((malCount/total)*100).toFixed(0) },
                { color:'#F4D35E', label:'Suspicious', pct:((susCount/total)*100).toFixed(0) },
                { color:'#9EFFBF', label:'Safe',       pct:((safeCount/total)*100).toFixed(0) },
              ].map(l => (
                <div key={l.label} className="flex items-center gap-1.5">
                  <div className="w-2 h-2" style={{ background: l.color }} />
                  <span className="font-mono text-[9px] text-[#6B6B68]">{l.label} {l.pct}%</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Filter tabs */}
        <div className="flex items-center gap-0 mb-0 border-b border-[rgba(58,58,56,0.2)]">
          {(['ALL','MALICIOUS','SUSPICIOUS','SAFE'] as FilterLevel[]).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-4 py-2 font-mono text-[10px] uppercase tracking-[0.1em] border-b-2 transition-colors ${
                filter === f ? 'border-[#1A3C2B] text-[#1A3C2B]' : 'border-transparent text-[#6B6B68] hover:text-[#1A3C2B]'
              }`}>
              {f}
              {f !== 'ALL' && <span className="ml-1 text-[8px]">({f==='MALICIOUS'?malCount:f==='SUSPICIOUS'?susCount:safeCount})</span>}
            </button>
          ))}
          <div className="ml-auto flex items-center gap-1.5 pb-2">
            <Activity className="w-3 h-3 text-[#6B6B68]" />
            <span className="font-mono text-[9px] text-[#6B6B68]">
              {isLive ? 'Auto-updating every 6–10s' : 'Backend offline'}
            </span>
          </div>
        </div>

        {/* Feed table */}
        <div className="bg-white border border-x border-b border-[rgba(58,58,56,0.2)] mb-8">
          {filtered.length === 0 ? (
            <div className="py-16 text-center">
              <Shield className="w-12 h-12 text-[rgba(26,60,43,0.15)] mx-auto mb-4" />
              <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-4">
                {scans.length === 0 ? 'AWAITING BACKEND CONNECTION' : `NO ${filter} ENTRIES`}
              </p>
              {scans.length === 0 && (
                <Link to="/scanner" className="inline-flex items-center gap-1 font-mono text-[10px] uppercase text-[#1A3C2B] hover:underline">
                  <ArrowRight className="w-3 h-3" /> Go to Scanner
                </Link>
              )}
            </div>
          ) : (
            <>
              {/* Column headers */}
              <div className="grid grid-cols-[1.2fr_2.5fr_1fr_1.2fr_0.8fr_0.7fr_0.8fr] px-4 py-2.5 bg-[rgba(26,60,43,0.03)] border-b border-[rgba(58,58,56,0.15)]">
                {['SCAN ID','FILE','THREAT','CONFIDENCE','PATH','MS','TIME'].map(h => (
                  <p key={h} className="font-mono text-[9px] uppercase tracking-[0.12em] text-[#6B6B68]">{h}</p>
                ))}
              </div>

              {/* Rows */}
              {filtered.map((scan: any) => (
                <div key={scan.scan_id}
                  className={`grid grid-cols-[1.2fr_2.5fr_1fr_1.2fr_0.8fr_0.7fr_0.8fr] px-4 py-3 border-b border-[rgba(58,58,56,0.07)] last:border-b-0 items-center hover:bg-[rgba(26,60,43,0.025)] transition-colors cursor-default ${
                    newIds.has(scan.scan_id) ? 'new-row' : ''
                  }`}>

                  {/* Scan ID */}
                  <p className="font-mono text-[10px] text-[#6B6B68]">{scan.scan_id}</p>

                  {/* Filename */}
                  <p className="text-[12px] text-[#1A1A18] truncate pr-3" title={scan.filename}>
                    {scan.filename}
                  </p>

                  {/* Threat */}
                  <div><ThreatChip level={scan.threat_level} size="sm" /></div>

                  {/* Confidence + mini bar */}
                  <div>
                    <p className="font-mono text-[11px] font-semibold mb-1"
                      style={{ color: scan.threat_level==='MALICIOUS'?'#FF8C69':scan.threat_level==='SUSPICIOUS'?'#b8942a':'#1A3C2B' }}>
                      {(scan.confidence_score * 100).toFixed(1)}%
                    </p>
                    <div className="w-16 h-1 bg-[rgba(58,58,56,0.1)]">
                      <div className="h-full transition-all duration-500"
                        style={{
                          width:`${scan.confidence_score*100}%`,
                          background:scan.threat_level==='MALICIOUS'?'#FF8C69':scan.threat_level==='SUSPICIOUS'?'#F4D35E':'#9EFFBF'
                        }} />
                    </div>
                  </div>

                  {/* Path badge */}
                  <span className={`inline-block px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-[0.06em] ${
                    scan.detection_path==='YARA_STATIC'
                      ? 'bg-[rgba(255,140,105,0.12)] text-[#d4613a]'
                      : 'bg-[rgba(244,211,94,0.12)] text-[#8a6e00]'
                  }`}>
                    {scan.detection_path==='YARA_STATIC' ? 'PATH A' : 'PATH B'}
                  </span>

                  {/* Processing ms */}
                  <p className="font-mono text-[9px] text-[#6B6B68]">{scan.processing_time_ms}ms</p>

                  {/* Timestamp */}
                  <p className="font-mono text-[9px] text-[#6B6B68]">{scan.ts}</p>
                </div>
              ))}
            </>
          )}
        </div>

        {/* Confidence chart */}
        {scans.length > 0 && (
          <div className="bg-white border border-[rgba(58,58,56,0.2)] p-6">
            <div className="flex items-center justify-between mb-4">
              <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68]">
                CONFIDENCE DISTRIBUTION — LAST 30 SCANS
              </p>
              <div className="flex gap-4">
                {[{color:'#FF8C69',label:'MALICIOUS'},{color:'#F4D35E',label:'SUSPICIOUS'},{color:'#9EFFBF',label:'SAFE'}].map(l=>(
                  <div key={l.label} className="flex items-center gap-1.5">
                    <div className="w-2 h-2" style={{background:l.color}} />
                    <span className="font-mono text-[9px] text-[#6B6B68]">{l.label}</span>
                  </div>
                ))}
              </div>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={chartData} barSize={8} margin={{top:0,right:0,left:-20,bottom:0}}>
                <CartesianGrid vertical={false} stroke="rgba(58,58,56,0.08)" />
                <XAxis dataKey="i" tick={false} axisLine={false} tickLine={false} />
                <YAxis domain={[0,100]}
                  tick={{fontFamily:'JetBrains Mono',fontSize:9,fill:'#6B6B68'}}
                  axisLine={false} tickLine={false}
                  tickFormatter={v=>`${v}%`} />
                <Tooltip
                  contentStyle={{background:'#fff',border:'1px solid rgba(58,58,56,0.2)',borderRadius:0,fontFamily:'JetBrains Mono',fontSize:10,padding:'6px 10px'}}
                  formatter={(v:any)=>[`${Number(v).toFixed(1)}%`,'Confidence']}
                  cursor={{fill:'rgba(26,60,43,0.04)'}} />
                <Bar dataKey="val" radius={[2,2,0,0]}>
                  {chartData.map((e:any,i:number)=>(
                    <Cell key={i} fill={barColor(e.level)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

      </div>
    </div>
  );
};

export default ThreatFeed;
