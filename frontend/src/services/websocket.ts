export interface TelemetryPulse {
  timestamp: string;
  activeFlows: number;
  throughputGbps: number;
  encryptedPct: number;
  eps: number;
  p95LatencyMs: number;
}

type PulseListener = (pulse: TelemetryPulse) => void;

class TelemetryStreamClient {
  private ws: WebSocket | null = null;
  private listeners = new Set<PulseListener>();
  private simTimer: number | null = null;
  private running = false;

  subscribe(listener: PulseListener): () => void {
    this.listeners.add(listener);
    if (!this.running) {
      this.start();
    }
    return () => {
      this.listeners.delete(listener);
      if (this.listeners.size === 0) {
        this.stop();
      }
    };
  }

  private start() {
    this.running = true;
    const wsUrl = (import.meta.env.VITE_WS_URL as string | undefined) || '';

    if (wsUrl) {
      try {
        this.ws = new WebSocket(wsUrl);
        this.ws.onmessage = (evt) => {
          try {
            const parsed = JSON.parse(String(evt.data)) as TelemetryPulse;
            this.emit(parsed);
          } catch {
            // ignore malformed frame
          }
        };
        this.ws.onerror = () => {
          this.startLocalFallback();
        };
        this.ws.onclose = () => {
          if (this.running) this.startLocalFallback();
        };
        return;
      } catch {
        this.startLocalFallback();
        return;
      }
    }

    this.startLocalFallback();
  }

  private startLocalFallback() {
    if (this.simTimer !== null) return;
    this.simTimer = window.setInterval(() => {
      const jitter = (range: number) => (Math.random() - 0.5) * range;
      const now = new Date();
      const pulse: TelemetryPulse = {
        timestamp: now.toTimeString().slice(0, 8),
        activeFlows: Math.round(14820 + jitter(420)),
        throughputGbps: Number((1.84 + jitter(0.18)).toFixed(2)),
        encryptedPct: Number((78.4 + jitter(0.9)).toFixed(1)),
        eps: Math.round(4280 + jitter(240)),
        p95LatencyMs: Number((4.2 + jitter(0.6)).toFixed(1)),
      };
      this.emit(pulse);
    }, 3000);
  }

  private emit(pulse: TelemetryPulse) {
    this.listeners.forEach((cb) => cb(pulse));
  }

  private stop() {
    this.running = false;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    if (this.simTimer !== null) {
      window.clearInterval(this.simTimer);
      this.simTimer = null;
    }
  }
}

export const telemetryStream = new TelemetryStreamClient();
