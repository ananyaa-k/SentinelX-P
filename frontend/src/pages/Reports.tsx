import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Download, ChevronDown, ChevronUp, ArrowRight, FileText, Activity } from 'lucide-react';
import { useScanContext } from '../context/ScanContext';
import ThreatChip from '../components/ThreatChip';
import { ScanResult } from '../types';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';
import {
  Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid
} from 'recharts';

const Reports: React.FC = () => {
  const { scans } = useScanContext();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState<string | null>(null);

  const generatePdfReport = async (scan: ScanResult, elementId: string) => {
    setIsGeneratingPdf(scan.scan_id);
    const element = document.getElementById(elementId);
    
    // We expand temporarily to allow html2canvas to capture it if it is not expanded.
    const wasExpanded = expandedId === scan.scan_id;
    if (!wasExpanded) {
      setExpandedId(scan.scan_id);
      // Let the DOM update first
      await new Promise(r => setTimeout(r, 500));
    }

    const captureElement = document.getElementById(elementId);
    if (!captureElement) {
      setIsGeneratingPdf(null);
      return;
    }

    try {
      const canvas = await html2canvas(captureElement, { scale: 2, useCORS: true, backgroundColor: '#ffffff' });
      const imgData = canvas.toDataURL('image/png');
      
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
      
      pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
      pdf.save(`SentinelX-Threat-Report-${scan.scan_id}.pdf`);
    } catch (e) {
      console.error('Failed to generate PDF:', e);
    } finally {
      if (!wasExpanded) setExpandedId(null);
      setIsGeneratingPdf(null);
    }
  };

  const getBorderColor = (level: string) => {
    switch (level) {
      case 'MALICIOUS': return 'border-l-[3px] border-l-[#FF8C69]';
      case 'SUSPICIOUS': return 'border-l-[3px] border-l-[#F4D35E]';
      case 'SAFE': return 'border-l-[3px] border-l-[#9EFFBF]';
      default: return '';
    }
  };

  const reportsToShow = scans.slice(0, 20);

  const formatRadarData = (features?: Record<string, number>) => {
    if (!features) return [];
    
    // Normalizing different features into a 0-100 scale for a good radar chart layout
    return [
      { subject: 'Entropy', A: Math.min((features.file_entropy || 0) * 12.5, 100) },
      { subject: 'Susp imports', A: Math.min((features.suspicious_import_count || 0) * 20, 100) },
      { subject: 'Susp strings', A: Math.min((features.suspicious_string_count || 0) * 10, 100) },
      { subject: 'Anti-Debug', A: Math.min((features.anti_debug_calls || 0) * 33, 100) },
      { subject: 'Network C2', A: Math.min((features.network_indicators || 0) * 25, 100) },
      { subject: 'Packing artifacts', A: (features.has_packing_artifacts || 0) * 100 },
    ];
  };

  return (
    <div className="min-h-screen pt-14 mosaic-bg" data-testid="reports-page">
      <div className="max-w-[1400px] mx-auto px-6 py-12">
        {/* Header */}
        <div className="mb-8">
          <h1 className="font-heading text-4xl font-bold text-[#1A3C2B] mb-2">REPORTS</h1>
          <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68]">
            — ANALYTICS & DOCUMENTATION
          </p>
        </div>

        {reportsToShow.length > 0 ? (
          <div className="flex flex-col gap-6">
            {reportsToShow.map((scan) => (
              <div 
                key={scan.scan_id} 
                id={`report-container-${scan.scan_id}`}
                className={`bg-white p-6 shadow-sm border border-[rgba(58,58,56,0.1)] ${getBorderColor(scan.threat_level)} relative`}
              >
                
                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                  
                  {/* Summary Block */}
                  <div className="flex-1">
                    <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-2">
                       REPORT ID: {scan.scan_id}
                    </p>
                    <h3 className="font-heading text-2xl font-bold text-[#1A3C2B] mb-3 flex items-center gap-3">
                      {scan.filename}
                      <ThreatChip level={scan.threat_level} size="sm" />
                    </h3>
                    
                    <div className="flex flex-wrap gap-x-6 gap-y-2 font-mono text-[11px] text-[#6B6B68] mb-4">
                      <span>TIMESTAMP: <span className="text-[#1A3C2B] font-bold">{scan.ts}</span></span>
                      <span>DETECTION PATH: <span className="text-[#1A3C2B] font-bold">{scan.detection_path}</span></span>
                      <span>PROCESSING TIME: <span className="text-[#1A3C2B] font-bold">{scan.processing_time_ms}ms</span></span>
                    </div>

                    {/* Threat Score Bar */}
                    <div className="mb-4 mt-2 max-w-sm">
                      <div className="flex justify-between text-[10px] font-mono tracking-widest mb-1 text-[#6B6B68]">
                        <span>CONFIDENCE SCORE</span>
                        <span>{(scan.confidence_score * 100).toFixed(1)}%</span>
                      </div>
                      <div className="h-[6px] bg-[rgba(58,58,56,0.1)] border border-[rgba(58,58,56,0.1)] w-full">
                        <div 
                          className={`h-full transition-all duration-300 ${
                            scan.threat_level === 'MALICIOUS' ? 'bg-[#FF8C69]' :
                            scan.threat_level === 'SUSPICIOUS' ? 'bg-[#F4D35E]' : 'bg-[#9EFFBF]'
                          }`}
                          style={{ width: `${scan.confidence_score * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex flex-row md:flex-col gap-3">
                    <button
                      onClick={() => setExpandedId(expandedId === scan.scan_id ? null : scan.scan_id)}
                      className="inline-flex justify-center items-center gap-1.5 px-4 py-2 border border-[rgba(58,58,56,0.2)] font-mono text-[10px] uppercase tracking-[0.1em] text-[#1A3C2B] hover:bg-[rgba(26,60,43,0.05)] transition-colors min-w-[150px]"
                      data-testid={`expand-${scan.scan_id}`}
                    >
                      {expandedId === scan.scan_id ? (
                        <><ChevronUp className="w-4 h-4" /> Hide Details</>
                      ) : (
                        <><ChevronDown className="w-4 h-4" /> View Details</>
                      )}
                    </button>
                    <button
                      onClick={() => generatePdfReport(scan, `report-container-${scan.scan_id}`)}
                      disabled={isGeneratingPdf === scan.scan_id}
                      className="inline-flex justify-center items-center gap-1.5 px-4 py-2 bg-[#1A3C2B] text-white font-mono text-[10px] uppercase tracking-[0.1em] hover:bg-[#2C4E3D] transition-colors disabled:opacity-50 min-w-[150px]"
                      data-testid={`download-${scan.scan_id}`}
                    >
                      <Download className="w-4 h-4" />
                      {isGeneratingPdf === scan.scan_id ? 'Generating...' : 'Download PDF'}
                    </button>
                  </div>
                </div>

                {/* Expanded Details - The Detailed Dashboard */}
                {expandedId === scan.scan_id && (
                  <div className="mt-8 pt-8 border-t border-[rgba(58,58,56,0.1)]">
                    <div className="grid lg:grid-cols-2 gap-8">
                      
                      {/* Left Column: AI & Text Analytics */}
                      <div className="space-y-6">
                        <div>
                          <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-2 flex items-center gap-2">
                             <Activity className="w-3 h-3"/> AI REASONING / VERDICT
                          </p>
                          <div className="bg-[rgba(26,60,43,0.02)] p-4 border border-[rgba(58,58,56,0.05)] rounded-sm">
                            <p className="text-sm text-[#1A1A18] leading-relaxed">
                              {scan.llm_analysis.reasoning}
                            </p>
                          </div>
                        </div>

                        {scan.llm_analysis.behavioral_flags.length > 0 && (
                          <div>
                            <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-2">BEHAVIORAL FLAGS</p>
                            <div className="flex flex-wrap gap-2">
                              {scan.llm_analysis.behavioral_flags.map((flag, i) => (
                                <span key={i} className="px-3 py-1.5 bg-[#F9F9F8] border border-[rgba(58,58,56,0.1)] font-mono text-[10px] text-[#1A3C2B]">
                                  • {flag}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        <div>
                           <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-2">RECOMMENDED ACTION</p>
                           <p className="text-sm font-semibold text-[#1A3C2B]">{scan.recommendation}</p>
                        </div>
                      </div>

                      {/* Right Column: Graphical Analytics & YARA */}
                      <div className="space-y-6">
                        {/* Radar Chart features */}
                        {scan.features_extracted && (
                          <div className="bg-[#F9F9F8] border border-[rgba(58,58,56,0.1)] p-4 pt-2">
                            <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-0 text-center">FEATURE VECTORS</p>
                            <div className="h-[220px] w-full">
                              <ResponsiveContainer width="100%" height="100%">
                                <RadarChart cx="50%" cy="50%" outerRadius="75%" data={formatRadarData(scan.features_extracted)}>
                                  <PolarGrid stroke="rgba(58,58,56,0.15)" />
                                  <PolarAngleAxis dataKey="subject" tick={{ fill: '#6B6B68', fontSize: 10, fontFamily: 'monospace' }} />
                                  <Radar name="Scanned File" dataKey="A" stroke="#1A3C2B" fill="#1A3C2B" fillOpacity={0.2} />
                                </RadarChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        )}

                        {scan.generated_yara_rule && (
                          <div>
                            <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#6B6B68] mb-2">YARA SIGNATURE RULE (AUTO-GENERATED)</p>
                            <pre className="code-block text-[11px] leading-relaxed whitespace-pre-wrap p-4 bg-[#1A1A18] text-[#E0E0E0] rounded-sm overflow-x-auto max-h-[300px] overflow-y-auto">
                              {scan.generated_yara_rule}
                            </pre>
                          </div>
                        )}
                      </div>

                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-white border border-[rgba(58,58,56,0.2)] py-20 text-center">
            <FileText className="w-16 h-16 text-[rgba(26,60,43,0.1)] mx-auto mb-4" />
            <p className="text-[#6B6B68] mb-6 font-mono text-sm tracking-widest uppercase">No reports in system memory</p>
            <Link
              to="/scanner"
              className="inline-flex items-center gap-2 px-8 py-4 bg-[#1A3C2B] text-white font-heading font-semibold text-sm uppercase tracking-wide hover:bg-[#2C4E3D] transition-colors"
            >
              <ArrowRight className="w-4 h-4" />
              Run Your First Scan
            </Link>
          </div>
        )}
      </div>
    </div>
  );
};

export default Reports;
