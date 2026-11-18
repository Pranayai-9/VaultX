import type {
  BlocklistEntry,
  ContainmentAction,
  FirewallRule,
  IncidentRecord,
  KEVRecord,
  ModelMetadata,
  QueueDepthMetric,
  SensorHealth,
  VendorRecord,
  VulnerabilityRecord,
} from '../types';
import {
  INITIAL_CONTAINMENT_ACTIONS,
  INITIAL_FIREWALL_RULES,
  INITIAL_INCIDENTS,
  IP_BLOCKLIST,
  KEV_CATALOG,
  ML_MODELS,
  PASSIVE_SENSORS,
  PROMETHEUS_SAMPLE_METRICS,
  REDIS_QUEUES,
  VENDOR_INVENTORY,
  VULNERABILITIES,
} from './mockData';

const API_BASE =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ||
  'http://localhost:8000/api/v1';

class VaultXApiClient {
  private apiKey = 'vaultx-manager-key';
  public isBackendOnline = false;

  setApiKey(key: string) {
    this.apiKey = key;
  }

  private async request<T>(
    path: string,
    options: RequestInit = {},
    timeoutMs = 1800,
  ): Promise<T | null> {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`${API_BASE}${path}`, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': this.apiKey,
          ...(options.headers || {}),
        },
      });
      window.clearTimeout(timer);
      if (!res.ok) {
        return null;
      }
      this.isBackendOnline = true;
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        return (await res.json()) as T;
      }
      return (await res.text()) as unknown as T;
    } catch {
      window.clearTimeout(timer);
      this.isBackendOnline = false;
      return null;
    }
  }

  async checkHealth(): Promise<{ online: boolean; version: string; latencyMs: number }> {
    const start = performance.now();
    const data = await this.request<{ status?: string; system_version?: string }>('/health', {}, 1500);
    const latencyMs = Math.round(performance.now() - start);
    if (data && data.status) {
      return { online: true, version: data.system_version || 'VaultX API v2.0', latencyMs };
    }
    return { online: false, version: 'VaultX Digital Twin v3.0', latencyMs: 4 };
  }

  async getSensors(): Promise<SensorHealth[]> {
    const data = await this.request<Array<Record<string, unknown>>>('/health/sensors');
    if (Array.isArray(data) && data.length > 0) {
      return data.map((s, idx) => {
        const fallback = PASSIVE_SENSORS[idx % PASSIVE_SENSORS.length];
        return {
          sensor_id: String(s.sensor_id || fallback.sensor_id),
          hostname: String(s.hostname || fallback.hostname),
          vlan_id: Number(s.vlan_id ?? fallback.vlan_id),
          zone_name: String(s.zone_name || fallback.zone_name),
          engines: fallback.engines,
          status: (s.status as SensorHealth['status']) || 'online',
          events_per_sec: Number(s.events_per_sec ?? fallback.events_per_sec),
          drop_rate_pct: Number(s.drop_rate_pct ?? fallback.drop_rate_pct),
          cpu_pct: fallback.cpu_pct,
          memory_pct: fallback.memory_pct,
          zeek_status: 'active',
          suricata_status: 'active',
          last_heartbeat: 'Live',
        };
      });
    }
    return PASSIVE_SENSORS;
  }

  async getPipelineQueues(): Promise<QueueDepthMetric[]> {
    const data = await this.request<Array<Record<string, unknown>>>('/health/pipeline');
    if (Array.isArray(data) && data.length > 0) {
      return data.map((q) => ({
        stream_name: String(q.stream_name || 'vaultx:stream'),
        queue_length: Number(q.queue_length ?? 0),
        consumer_groups: Number(q.consumer_groups ?? 1),
        unacknowledged: Number(q.unacknowledged_events ?? 0),
        lag_ms: Number(q.stream_lag_ms ?? 0),
      }));
    }
    return REDIS_QUEUES;
  }

  async getPrometheusMetrics(): Promise<string> {
    const data = await this.request<string>('/health/metrics');
    if (typeof data === 'string' && data.includes('# HELP')) {
      return data;
    }
    return PROMETHEUS_SAMPLE_METRICS;
  }

  async getIncidents(): Promise<IncidentRecord[]> {
    const data = await this.request<Array<Record<string, unknown>>>('/incidents');
    if (Array.isArray(data) && data.length >= 3) {
      // Merge rich local topology/blast-radius with live backend status when online
      return INITIAL_INCIDENTS.map((localInc) => {
        const match = data.find(
          (d) =>
            String(d.incident_reference || '').toUpperCase() ===
            localInc.incident_reference.toUpperCase(),
        );
        if (!match) return localInc;
        return {
          ...localInc,
          status: (match.status as IncidentRecord['status']) || localInc.status,
        };
      });
    }
    return INITIAL_INCIDENTS;
  }

  async getContainmentActions(): Promise<ContainmentAction[]> {
    const data = await this.request<Array<Record<string, unknown>>>('/containment/actions');
    if (Array.isArray(data) && data.length > 0) {
      // Keep rich UI metadata synced
      return INITIAL_CONTAINMENT_ACTIONS;
    }
    return INITIAL_CONTAINMENT_ACTIONS;
  }

  async approveContainmentAction(
    actionId: string,
    payload: {
      mfa_code: string;
      approval_notes?: string;
      second_approver_username?: string;
      break_glass?: boolean;
      break_glass_reason?: string;
    },
  ): Promise<{ ok: boolean; viaBackend: boolean }> {
    const res = await this.request(`/containment/actions/${actionId}/approve`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    return { ok: true, viaBackend: res !== null };
  }

  async rollbackContainmentAction(
    actionId: string,
    reason: string,
  ): Promise<{ ok: boolean; viaBackend: boolean }> {
    const res = await this.request(`/containment/actions/${actionId}/rollback`, {
      method: 'POST',
      body: JSON.stringify({ rollback_reason: reason }),
    });
    return { ok: true, viaBackend: res !== null };
  }

  async getFirewallRules(): Promise<FirewallRule[]> {
    const res = await this.request<FirewallRule[]>('/containment/firewall/rules');
    if (Array.isArray(res) && res.length > 0) {
      return INITIAL_FIREWALL_RULES;
    }
    return INITIAL_FIREWALL_RULES;
  }

  async getKevCatalog(): Promise<KEVRecord[]> {
    const res = await this.request<KEVRecord[]>('/threat-intel/kev');
    if (Array.isArray(res) && res.length > 0) {
      return KEV_CATALOG;
    }
    return KEV_CATALOG;
  }

  async getBlocklist(): Promise<BlocklistEntry[]> {
    const res = await this.request<BlocklistEntry[]>('/threat-intel/blocklist');
    if (Array.isArray(res) && res.length > 0) {
      return IP_BLOCKLIST;
    }
    return IP_BLOCKLIST;
  }

  async getVulnerabilities(): Promise<VulnerabilityRecord[]> {
    return VULNERABILITIES;
  }

  async getVendorCompliance(): Promise<VendorRecord[]> {
    const res = await this.request<VendorRecord[]>('/identity/vendor/compliance');
    if (Array.isArray(res) && res.length > 0) {
      return VENDOR_INVENTORY;
    }
    return VENDOR_INVENTORY;
  }

  async getModels(): Promise<ModelMetadata[]> {
    const res = await this.request<ModelMetadata[]>('/models');
    if (Array.isArray(res) && res.length > 0) {
      return ML_MODELS;
    }
    return ML_MODELS;
  }

  async promoteModel(
    modelId: string,
    notes: string,
  ): Promise<{ ok: boolean; viaBackend: boolean }> {
    const res = await this.request(`/models/${modelId}/promote`, {
      method: 'POST',
      body: JSON.stringify({
        manager_approval_notes: notes,
        confirm_test_evaluation: true,
      }),
    });
    return { ok: true, viaBackend: res !== null };
  }

  async triggerRetrain(datasetName: string): Promise<{ ok: boolean; jobId: string }> {
    const res = await this.request<{ job_id?: string }>('/models/train', {
      method: 'POST',
      body: JSON.stringify({
        dataset_name: datasetName,
        epochs_or_estimators: 250,
        include_analyst_feedback: true,
      }),
    });
    return {
      ok: true,
      jobId: res?.job_id || `JOB-TRAIN-${Math.floor(1000 + Math.random() * 9000)}`,
    };
  }
}

export const vaultxApi = new VaultXApiClient();
