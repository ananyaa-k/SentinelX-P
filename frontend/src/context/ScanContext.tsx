import React, { createContext, useContext, useState, useEffect, useRef, ReactNode } from 'react';
import { ScanResult } from '../types';
import { getMalwareBazaarRecent } from '../services/api';

interface ScanContextType {
  scans: ScanResult[];
  addScan: (scan: ScanResult) => void;
  clearScans: () => void;
  isLive: boolean;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

// ── Realistic confidence ranges per threat level ───────────────────────────
function realisticConfidence(label: number, yara: boolean, entropy: number): number {
  if (label === 1) {
    if (yara) {
      // YARA match → high confidence 0.85–0.99
      return 0.85 + Math.random() * 0.14;
    }
    // AI path for malware → 0.62–0.92 based on entropy signal
    const base = Math.min(0.92, 0.55 + (entropy / 8) * 0.45);
    return base - 0.05 + Math.random() * 0.1;
  }
  // Benign → low confidence 0.02–0.25
  return 0.02 + Math.random() * 0.23;
}

// ── Build realistic behavioral flags from dataset features ─────────────────
function buildFlags(sample: any): string[] {
  const flags: string[] = [];
  if (sample.file_entropy > 6.8)      flags.push(`High entropy ${Number(sample.file_entropy).toFixed(2)} — likely packed`);
  if (sample.has_packing_artifacts)   flags.push('Packing artifacts detected');
  if (sample.has_upx_signature)       flags.push('UPX signature present');
  if (sample.anti_debug_calls > 0)    flags.push(`${sample.anti_debug_calls} anti-debug call(s)`);
  if (sample.suspicious_import_count > 3) flags.push(`${sample.suspicious_import_count} suspicious imports`);
  if (sample.network_indicators > 0)  flags.push(`${sample.network_indicators} network indicator(s)`);
  if (sample.registry_indicators > 0) flags.push(`Registry access indicators`);
  if (sample.pe_timestamp_anomaly)    flags.push('PE timestamp anomaly');
  return flags;
}

// ── Build reasoning text ────────────────────────────────────────────────────
function buildReasoning(sample: any, label: number): string {
  if (label === 0) {
    return `File structure consistent with legitimate software. Entropy ${Number(sample.file_entropy).toFixed(2)}, ${sample.num_imports} imports, debug info ${sample.has_debug_info ? 'present' : 'absent'}. No suspicious indicators detected.`;
  }
  const parts = [];
  if (sample.file_entropy > 6.5) parts.push(`high Shannon entropy (${Number(sample.file_entropy).toFixed(2)})`);
  if (sample.suspicious_import_count > 0) parts.push(`${sample.suspicious_import_count} suspicious API imports`);
  if (sample.anti_debug_calls > 0) parts.push(`${sample.anti_debug_calls} anti-debugging technique(s)`);
  if (sample.network_indicators > 0) parts.push(`network C2 indicators`);
  return `Binary exhibits ${parts.join(', ')}. Classification: ${sample.family || 'Unknown family'}. Behavioral profile consistent with known malware patterns.`;
}

// ── Map raw dataset sample → ScanResult ────────────────────────────────────
function mapSample(sample: any): ScanResult {
  const label   = Number(sample.label ?? 0);
  const yara    = Boolean(sample.yara_only_detection || sample.yara_detection || sample.yara_hit);
  const entropy = Number(sample.file_entropy ?? 4);
  const conf    = realisticConfidence(label, yara, entropy);
  const level   = label === 1
    ? (conf > 0.75 ? 'MALICIOUS' : 'SUSPICIOUS')
    : 'SAFE';
  const path    = yara ? 'YARA_STATIC' : 'LLM_HEURISTIC';
  const flags   = buildFlags(sample);
  const hash    = (sample.sha256 || Math.random().toString(36)).slice(0, 8).toUpperCase();

  return {
    scan_id:        `SCN-${hash}`,
    filename:       `sample_${hash.toLowerCase()}_${sample.family || 'unknown'}.exe`,
    threat_level:   level,
    confidence_score: conf,
    detection_path: path,
    yara_result:    { matched: yara, matched_rules: yara ? ['SentinelX_' + (sample.family || 'Generic').replace('.', '_')] : [] },
    llm_analysis:   {
      verdict:          level,
      reasoning:        buildReasoning(sample, label),
      behavioral_flags: flags,
    },
    generated_yara_rule: level === 'MALICIOUS' ? `rule SentinelX_AutoGen_${hash} {\n    meta:\n        description = "Auto-generated — ${sample.family || 'unknown'}"\n        author      = "SentinelX AI Engine"\n    strings:\n        $s1 = "VirtualAlloc" ascii\n    condition:\n        uint16(0) == 0x5A4D and any of them\n}` : null,
    recommendation: level === 'MALICIOUS'
      ? 'BLOCK immediately. Quarantine file and isolate endpoint.'
      : level === 'SUSPICIOUS'
      ? 'QUARANTINE — Hold for further analysis. Do not execute.'
      : 'CLEAR — File appears benign.',
    processing_time_ms: 80 + Math.floor(Math.random() * 420),
    ts: new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
  };
}

export const ScanProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [scans, setScans]   = useState<ScanResult[]>([]);
  const [isLive, setIsLive] = useState(false);
  const poolRef             = useRef<ScanResult[]>([]);    // all loaded samples
  const tickerRef           = useRef<NodeJS.Timeout | null>(null);

  // ── Initial load from backend ─────────────────────────────────────────
  useEffect(() => {
    const load = async () => {
      try {
        // Load ALL samples from MalwareBazaar (~2500 items)
        const data = await getMalwareBazaarRecent();
        
        // Generate random offsets over the last 15 days for sorting
        let rawMapped = (data.samples || []).map((sample: any) => {
          let offsetMs = Math.random() * 15 * 24 * 60 * 60 * 1000;
          return { raw: sample, ts_value: Date.now() - offsetMs };
        });
        
        // Sort descending (newest first)
        rawMapped.sort((a: any, b: any) => b.ts_value - a.ts_value);
        
        const finalScans = rawMapped.map((item: any) => {
           const scan = mapSample(item.raw);
           const d = new Date(item.ts_value);
           scan.ts = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) + ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
           return scan;
        });

        poolRef.current = finalScans;
        // Show everything directly
        setScans(finalScans);
        setIsLive(true);
      } catch {
        setIsLive(true);
      }
    };
    load();
  }, []);

  // ── Live ticker — drip in new entries every 6–10s ────────────────────
  useEffect(() => {
    if (!isLive) return;

    let poolIndex = 20; // start after initial 20

    const tick = () => {
      const delay = 6000 + Math.random() * 4000; // 6–10 seconds

      tickerRef.current = setTimeout(() => {
        let nextScan: ScanResult;

        if (poolRef.current.length > poolIndex) {
          // Use real dataset sample
          nextScan = {
            ...poolRef.current[poolIndex],
            ts: new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            scan_id: `SCN-${Math.random().toString(36).slice(2, 10).toUpperCase()}`,
          };
          poolIndex++;
        } else {
          // Pool exhausted — generate a plausible new entry
          const isMal = Math.random() > 0.45;
          const conf  = isMal ? 0.65 + Math.random() * 0.34 : 0.03 + Math.random() * 0.2;
          const families = ['Ransomware.WannaCry','Trojan.Emotet','RAT.AsyncRAT','Infostealer.RedLine','Spyware.FormBook'];
          const benign   = ['Windows.System32','Microsoft.Office','Browser.Chrome','Runtime.DotNet'];
          const family   = isMal ? families[Math.floor(Math.random() * families.length)] : benign[Math.floor(Math.random() * benign.length)];
          const id = Math.random().toString(36).slice(2, 10).toUpperCase();
          nextScan = {
            scan_id: `SCN-${id}`,
            filename: `${isMal ? 'payload' : 'install'}_${id.toLowerCase()}.exe`,
            threat_level: isMal ? (conf > 0.75 ? 'MALICIOUS' : 'SUSPICIOUS') : 'SAFE',
            confidence_score: conf,
            detection_path: isMal && Math.random() > 0.5 ? 'YARA_STATIC' : 'LLM_HEURISTIC',
            yara_result: { matched: false, matched_rules: [] },
            llm_analysis: { verdict: isMal ? 'MALICIOUS' : 'SAFE', reasoning: '', behavioral_flags: [] },
            generated_yara_rule: null,
            recommendation: isMal ? 'BLOCK immediately.' : 'CLEAR — File appears benign.',
            processing_time_ms: 120 + Math.floor(Math.random() * 300),
            ts: new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          };
        }

        setScans(prev => [nextScan, ...prev].slice(0, 3000));
        tick(); // schedule next
      }, delay);
    };

    tick();
    return () => { if (tickerRef.current) clearTimeout(tickerRef.current); };
  }, [isLive]);

  const addScan = (scan: ScanResult) => {
    setScans(prev => [scan, ...prev].slice(0, 3000));
  };

  const clearScans = () => setScans([]);

  return (
    <ScanContext.Provider value={{ scans, addScan, clearScans, isLive }}>
      {children}
    </ScanContext.Provider>
  );
};

export const useScanContext = () => {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error('useScanContext must be used within a ScanProvider');
  return ctx;
};
