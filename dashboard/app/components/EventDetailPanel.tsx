"use client";

import { useEffect } from "react";
import { X } from "lucide-react";

const ATTACK_COLORS: Record<string, string> = {
  direct_injection: "#ef4444",
  prompt_leaking: "#f97316",
  jailbreak_persona: "#eab308",
  roleplay_framing: "#8b5cf6",
  hypothetical_framing: "#06b6d4",
  indirect_injection: "#ec4899",
  obfuscation: "#14b8a6",
  many_shot: "#f59e0b",
  privilege_escalation: "#dc2626",
  adversarial_suffix: "#7c3aed",
  benign: "#22c55e",
};

export type EventDetail = {
  id: string;
  timestamp: string;
  attack_type: string;
  confidence: number;
  blocked: boolean;
  layer_triggered: number;
  matched_patterns?: string[];
  latency_ms?: number;
  model?: string;
};

export default function EventDetailPanel({
  event,
  onClose,
}: {
  event: EventDetail | null;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!event) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [event, onClose]);

  if (!event) return null;

  const color = ATTACK_COLORS[event.attack_type] ?? "#6b7280";
  const pct = Math.round(event.confidence * 100);

  return (
    <>
      {/* backdrop */}
      <div
        className="fixed inset-0 bg-black/60 z-40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* panel */}
      <aside className="fixed top-0 right-0 h-full w-full max-w-md bg-zinc-900 border-l border-zinc-800 z-50 overflow-y-auto flex flex-col">
        <div className="flex items-center justify-between p-5 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Event Detail</h2>
          <button
            onClick={onClose}
            className="text-zinc-500 hover:text-zinc-200 transition-colors"
            aria-label="Close panel"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-5 flex-1">
          {/* timestamp */}
          <Row label="Timestamp">
            <span className="font-mono text-xs text-zinc-300">{event.timestamp}</span>
          </Row>

          {/* attack type */}
          <Row label="Attack Type">
            <span
              className="text-xs px-2 py-0.5 rounded-full font-medium"
              style={{ backgroundColor: color + "22", color }}
            >
              {event.attack_type.replace(/_/g, " ")}
            </span>
          </Row>

          {/* confidence */}
          <Row label="Confidence">
            <div className="flex items-center gap-3 flex-1">
              <div className="flex-1 bg-zinc-800 rounded-full h-2 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${pct}%`, backgroundColor: color }}
                />
              </div>
              <span className="text-xs text-zinc-300 w-10 text-right">{pct}%</span>
            </div>
          </Row>

          {/* layer */}
          <Row label="Layer Triggered">
            <span className="text-xs text-zinc-300">
              {event.layer_triggered === 1 ? "1 — Heuristics" : "2 — Semantic"}
            </span>
          </Row>

          {/* status */}
          <Row label="Status">
            {event.blocked ? (
              <span className="text-xs font-semibold text-red-400 bg-red-900/30 px-2 py-0.5 rounded-full">
                BLOCKED
              </span>
            ) : (
              <span className="text-xs font-semibold text-green-400 bg-green-900/30 px-2 py-0.5 rounded-full">
                ALLOWED
              </span>
            )}
          </Row>

          {/* latency */}
          {event.latency_ms != null && (
            <Row label="Latency">
              <span className="text-xs text-zinc-300">{event.latency_ms} ms</span>
            </Row>
          )}

          {/* model */}
          {event.model && (
            <Row label="Model">
              <span className="text-xs text-zinc-300 font-mono">{event.model}</span>
            </Row>
          )}

          {/* matched patterns */}
          <div>
            <p className="text-xs text-zinc-500 mb-2">Matched Patterns</p>
            {event.matched_patterns && event.matched_patterns.length > 0 ? (
              <ul className="space-y-1">
                {event.matched_patterns.map((p, i) => (
                  <li
                    key={i}
                    className="text-xs font-mono bg-zinc-800 text-zinc-300 px-2 py-1 rounded"
                  >
                    {p}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-zinc-600">None recorded</p>
            )}
          </div>
        </div>
      </aside>
    </>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-4">
      <p className="text-xs text-zinc-500 w-36 shrink-0">{label}</p>
      <div className="flex items-center gap-2 flex-1">{children}</div>
    </div>
  );
}
