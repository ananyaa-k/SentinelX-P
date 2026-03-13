import axios from 'axios';
import { ScanResult, BenchmarkResults, DatasetInfo, ModelInfo, FeatureImportance } from '../types';

const API_BASE = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000,
});

// File Analysis
export const analyzeFile = async (file: File): Promise<ScanResult> => {
  const formData = new FormData();
  formData.append('file', file);

  const response = await api.post('/analyze/file', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
};

// Health check
export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

// Benchmark
export const getBenchmarkResults = async (): Promise<BenchmarkResults> => {
  const response = await api.get('/benchmark/results');
  return response.data;
};

export const runBenchmark = async (n_samples: number = 30) => {
  const response = await api.post(`/benchmark/run?n_samples=${n_samples}`);
  return response.data;
};

// Dataset
export const getDatasetInfo = async (): Promise<DatasetInfo> => {
  const response = await api.get('/dataset/info');
  return response.data;
};

export const getDatasetSamples = async (page: number = 1, per_page: number = 20, label?: number) => {
  const params = new URLSearchParams({ page: String(page), per_page: String(per_page) });
  if (label !== undefined) params.append('label', String(label));
  const response = await api.get(`/dataset/samples?${params}`);
  return response.data;
};

// Model
export const getModelExplanation = async (): Promise<{ top_features: FeatureImportance[] }> => {
  const response = await api.get('/model/explain');
  return response.data;
};

export const getModelInfo = async (): Promise<ModelInfo> => {
  const response = await api.get('/model/info');
  return response.data;
};

export default api;
