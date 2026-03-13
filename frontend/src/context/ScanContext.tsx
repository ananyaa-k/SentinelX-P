import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { ScanResult } from '../types';
import { getDatasetSamples } from '../services/api';

interface ScanContextType {
  scans: ScanResult[];
  addScan: (scan: ScanResult) => void;
  clearScans: () => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export const ScanProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [scans, setScans] = useState<ScanResult[]>([]);

  useEffect(() => {
    const fetchInitial = async () => {
      try {
        const data = await getDatasetSamples(1, 20);
        const mapped: ScanResult[] = data.samples.map((s: any) => ({
          scan_id: `SCN-${s.sha256.substring(0, 8).toUpperCase()}`,
          filename: `sample_${s.sha256.substring(0, 6)}_${s.family}.exe`,
          threat_level: s.threat_score > 0.8 ? 'MALICIOUS' : s.threat_score > 0.46 ? 'SUSPICIOUS' : 'SAFE',
          confidence_score: s.threat_score,
          detection_path: s.yara_detection ? 'YARA_STATIC' : 'AI_HEURISTIC',
          yara_result: { matched: s.yara_detection, matched_rules: [] },
          llm_analysis: { verdict: '', reasoning: '', behavioral_flags: [] },
          generated_yara_rule: null,
          recommendation: '',
          processing_time_ms: Math.floor(Math.random() * 500) + 100,
          ts: new Date().toISOString().replace('T', ' ').substring(0, 19),
        }));
        setScans(mapped);
      } catch (e) {
        console.error("Failed to load initial samples", e);
      }
    };
    fetchInitial();
  }, []);

  const addScan = (scan: ScanResult) => {
    setScans((prev) => {
      const updated = [scan, ...prev];
      return updated.slice(0, 50); // Max 50 entries
    });
  };

  const clearScans = () => {
    setScans([]);
  };

  return (
    <ScanContext.Provider value={{ scans, addScan, clearScans }}>
      {children}
    </ScanContext.Provider>
  );
};

export const useScanContext = () => {
  const context = useContext(ScanContext);
  if (context === undefined) {
    throw new Error('useScanContext must be used within a ScanProvider');
  }
  return context;
};
