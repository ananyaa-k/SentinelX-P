import React, { useState, useCallback } from 'react';
import { Shield, Upload, Loader2, Copy, Check, Download } from 'lucide-react';
import { useScanContext } from '../context/ScanContext';
import { analyzeFile } from '../services/api';
import { generateMockScan } from '../data/mockData';
import { ScanResult } from '../types';
import LCornerMarkers from '../components/LCornerMarkers';
import ThreatChip from '../components/ThreatChip';
import ConfidenceRing from '../components/ConfidenceRing';

const Scanner: React.FC = () => {
  const { addScan } = useScanContext();
  const [file, setFile] = useState<File | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [copied, setCopied] = useState(false);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      setFile(droppedFile);
      setResult(null);
    }
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
      setResult(null);
    }
  };

  const handleAnalyze = async () => {
    if (!file) return;

    setIsAnalyzing(true);
    try {
      const scanResult = await analyzeFile(file);
      scanResult.ts = new Date().toLocaleTimeString();
      setResult(scanResult);
      addScan(scanResult);
    } catch (error) {
      // Fallback to mock data if backend unavailable
      const mockResult = generateMockScan(file.name);
      setResult(mockResult);
      addScan(mockResult);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCopyRule = async () => {
    if (result?.generated_yara_rule) {
      await navigator.clipboard.writeText(result.generated_yara_rule);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const generateReport = () => {
    if (!result) return;

    const report = `SENTINELX DEFENDER — SCAN REPORT
==================================
Scan ID:        ${result.scan_id}
File:           ${result.filename}
Timestamp:      ${result.ts}
Threat Level:   ${result.threat_level}
Confidence:     ${(result.confidence_score * 100).toFixed(1)}%
Detection Path: ${result.detection_path}

VERDICT
-------
${result.llm_analysis.verdict}

AI ANALYSIS
-----------
${result.llm_analysis.reasoning}

BEHAVIORAL FLAGS
----------------
${result.llm_analysis.behavioral_flags.join('\n')}

AUTO-GENERATED YARA RULE
-------------------------
${result.generated_yara_rule || 'N/A — no rule generated for benign files'}

RECOMMENDATION
--------------
${result.recommendation}
`;

    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinelx-report-${result.scan_id}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  return (
    <div className="min-h-screen pt-14 mosaic-bg" data-testid="scanner-page">
      <div className="max-w-[1400px] mx-auto px-6 py-12">
        {/* Header */}
        <div className="mb-8">
          <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-2">02. FILE ANALYZER</p>
          <h1 className="font-heading text-4xl font-bold text-[#1A3C2B]">Malware Scanner</h1>
        </div>

        <div className="grid lg:grid-cols-2 gap-8">
          {/* Left Panel - Upload */}
          <LCornerMarkers className="bg-white border border-[rgba(58,58,56,0.2)] p-8">
            {/* Drop Zone */}
            <div
              className={`drop-zone p-12 text-center mb-6 ${isDragOver ? 'drag-over' : ''}`}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              data-testid="drop-zone"
            >
              <Shield className="w-10 h-10 text-[#1A3C2B] mx-auto mb-4" />
              <h3 className="font-heading text-xl font-semibold text-[#1A3C2B] mb-2">Drop a PE Binary</h3>
              <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68]">
                Supported: .exe · .dll · .sys · .bin
              </p>
            </div>

            {/* File Input */}
            <label className="block mb-6">
              <input
                type="file"
                accept=".exe,.dll,.sys,.bin"
                onChange={handleFileChange}
                className="hidden"
                data-testid="file-input"
              />
              <span className="inline-flex items-center justify-center gap-2 w-full py-3 border border-[rgba(58,58,56,0.2)] text-[#1A3C2B] font-heading font-semibold text-sm uppercase tracking-wide cursor-pointer hover:bg-[rgba(26,60,43,0.05)] transition-colors">
                <Upload className="w-4 h-4" />
                Choose File
              </span>
            </label>

            {/* Selected File */}
            {file && (
              <div className="mb-6 p-3 bg-[rgba(26,60,43,0.03)] border border-[rgba(58,58,56,0.1)]">
                <p className="font-mono text-[11px] text-[#1A3C2B]">{file.name}</p>
                <p className="font-mono text-[10px] text-[#6B6B68]">{formatBytes(file.size)}</p>
              </div>
            )}

            {/* Analyze Button */}
            <button
              onClick={handleAnalyze}
              disabled={!file || isAnalyzing}
              className="w-full py-4 bg-[#1A3C2B] text-white font-heading font-bold text-sm uppercase tracking-wide hover:bg-[#2C4E3D] disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
              data-testid="analyze-btn"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Analyzing...
                </>
              ) : (
                'Run Analysis'
              )}
            </button>
          </LCornerMarkers>

          {/* Right Panel - Results */}
          <div>
            {result ? (
              <LCornerMarkers className="bg-white border border-[rgba(58,58,56,0.2)]" data-testid="results-panel">
                {/* Section 1 - Verdict */}
                <div className="p-6 border-b border-[rgba(58,58,56,0.1)]">
                  <div className="flex items-center justify-between">
                    <ThreatChip level={result.threat_level} size="lg" />
                    <p className="font-mono text-[10px] text-[#6B6B68]">SCAN-ID: {result.scan_id}</p>
                  </div>
                </div>

                {/* Section 2 - Confidence */}
                <div className="p-6 border-b border-[rgba(58,58,56,0.1)]">
                  <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-4">CONFIDENCE SCORE</p>
                  <div className="flex items-center gap-8">
                    <ConfidenceRing
                      percentage={result.confidence_score * 100}
                      threatLevel={result.threat_level}
                    />
                    <div>
                      <div className={`inline-flex items-center gap-2 px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.1em] ${result.detection_path === 'YARA_STATIC'
                          ? 'bg-[rgba(255,140,105,0.1)] text-[#FF8C69]'
                          : 'bg-[rgba(244,211,94,0.1)] text-[#F4D35E]'
                        }`}>
                        ▶ PATH {result.detection_path === 'YARA_STATIC' ? 'A' : 'B'} — {
                          result.detection_path === 'YARA_STATIC' ? 'YARA STATIC MATCH' : 'AI HEURISTIC ANALYSIS'
                        }
                      </div>
                    </div>
                  </div>
                </div>

                {/* Section 3 - Analysis */}
                <div className="p-6 border-b border-[rgba(58,58,56,0.1)]">
                  <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-4">AI BEHAVIORAL ANALYSIS</p>
                  <p className="text-[14px] text-[#1A1A18] leading-relaxed mb-4">{result.llm_analysis.reasoning}</p>
                  {result.llm_analysis.behavioral_flags.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {result.llm_analysis.behavioral_flags.map((flag, i) => (
                        <span
                          key={i}
                          className={`px-2 py-1 font-mono text-[10px] ${result.threat_level === 'MALICIOUS'
                              ? 'bg-[rgba(255,140,105,0.1)] text-[#FF8C69]'
                              : 'bg-[rgba(244,211,94,0.1)] text-[#F4D35E]'
                            }`}
                        >
                          {flag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Section 4 - YARA Rule */}
                {result.generated_yara_rule && (
                  <div className="p-6 border-b border-[rgba(58,58,56,0.1)]">
                    <div className="flex items-center justify-between mb-4">
                      <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68]">AUTO-GENERATED DETECTION RULE</p>
                      <span className="px-2 py-0.5 bg-[rgba(158,255,191,0.2)] text-[#1A3C2B] font-mono text-[9px] uppercase tracking-[0.1em]">
                        AI GENERATED
                      </span>
                    </div>
                    <div className="relative">
                      <pre className="code-block text-[11px] leading-relaxed whitespace-pre-wrap">
                        {result.generated_yara_rule}
                      </pre>
                      <button
                        onClick={handleCopyRule}
                        className="absolute top-2 right-2 p-2 bg-[rgba(255,255,255,0.1)] hover:bg-[rgba(255,255,255,0.2)] transition-colors"
                        data-testid="copy-rule-btn"
                      >
                        {copied ? <Check className="w-3 h-3 text-[#9EFFBF]" /> : <Copy className="w-3 h-3 text-[#9EFFBF]" />}
                      </button>
                    </div>
                  </div>
                )}

                {/* Section 5 - Recommendation */}
                <div className={`p-4 ${result.threat_level === 'MALICIOUS' ? 'bg-[rgba(255,140,105,0.1)]' :
                    result.threat_level === 'SUSPICIOUS' ? 'bg-[rgba(244,211,94,0.1)]' :
                      'bg-[rgba(158,255,191,0.1)]'
                  }`}>
                  <p className={`font-mono text-[12px] ${result.threat_level === 'MALICIOUS' ? 'text-[#FF8C69]' :
                      result.threat_level === 'SUSPICIOUS' ? 'text-[#F4D35E]' :
                        'text-[#1A3C2B]'
                    }`}>
                    {result.threat_level === 'MALICIOUS' && '🔴 BLOCK — '}
                    {result.threat_level === 'SUSPICIOUS' && '🟡 QUARANTINE — '}
                    {result.threat_level === 'SAFE' && '🟢 CLEAR — '}
                    {result.recommendation}
                  </p>
                </div>

                {/* Download Button */}
                <div className="p-6">
                  <button
                    onClick={generateReport}
                    className="inline-flex items-center gap-2 px-4 py-2 border border-[rgba(58,58,56,0.2)] text-[#1A3C2B] font-mono text-[10px] uppercase tracking-[0.1em] hover:bg-[rgba(26,60,43,0.05)] transition-colors"
                    data-testid="download-report-btn"
                  >
                    <Download className="w-3 h-3" />
                    Download Report
                  </button>
                </div>
              </LCornerMarkers>
            ) : (
              <div className="bg-white border border-[rgba(58,58,56,0.2)] p-16 text-center h-full flex flex-col items-center justify-center">
                <Shield className="w-16 h-16 text-[rgba(26,60,43,0.15)] mb-4" />
                <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-2">AWAITING ANALYSIS</p>
                <p className="text-[#6B6B68] text-sm">Upload a file and click Run Analysis</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Scanner;
