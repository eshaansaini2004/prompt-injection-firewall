"use client";

import { useEffect, useState, useCallback } from "react";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from "recharts";
import { Shield, ShieldAlert, Clock, Activity } from "lucide-react";
import { fetchStats, fetchTimeline, fetchAttackTypes, createEventSocket } from "@/lib/api";

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

function StatCard({
  icon: Icon,
  label,
  value,
  color = "text-white",
}: {
  icon: React.ElementType;
  label: string;
  value: string | number;
  color?: string;
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 flex gap-4 items-start">
      <div className="bg-zinc-800 rounded-lg p-2 mt-0.5">
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <div>
        <p className="text-zinc-400 text-sm">{label}</p>
        <p className={`text-2xl font-bold mt-0.5 ${color}`}>{value}</p>
      </div>
    </div>
  );
}

function AttackBadge({ type }: { type: string }) {
  const color = ATTACK_COLORS[type] ?? "#6b7280";
  return (
    <span
      className="text-xs px-2 py-0.5 rounded-full font-medium"
      style={{ backgroundColor: color + "22", color }}
    >
      {type.replace(/_/g, " ")}
    </span>
  );
}

type StatsData = { total_requests: number; blocked_total: number; block_rate: number; avg_latency_ms: number };
type TimelineBucket = { hour: string; total: number; blocked: number };
type AttackTypeCount = { attack_type: string; count: number };
type LiveEvent = { id: string; timestamp: string; attack_type: string; confidence: number; blocked: boolean; layer_triggered: number };

export default function Dashboard() {
  const [stats, setStats] = useState<StatsData | null>(null);
  const [timeline, setTimeline] = useState<TimelineBucket[]>([]);
  const [attackTypes, setAttackTypes] = useState<AttackTypeCount[]>([]);
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);

  const loadData = useCallback(async () => {
    const [s, t, a] = await Promise.all([fetchStats(), fetchTimeline(24), fetchAttackTypes()]);
    setStats(s);
    setTimeline(t);
    setAttackTypes(a);
  }, []);

  useEffect(() => {
    loadData();
    const ws = createEventSocket((event) => {
      setLiveEvents((prev) => [event as LiveEvent, ...prev].slice(0, 20));
      loadData();
    });
    return () => ws.close();
  }, [loadData]);

  return (
    <main className="min-h-screen bg-zinc-950 text-white p-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-3 mb-8">
          <ShieldAlert className="w-7 h-7 text-red-500" />
          <h1 className="text-2xl font-bold">Prompt Injection Firewall</h1>
          <span className="ml-auto text-xs bg-green-900 text-green-400 px-2 py-1 rounded-full">LIVE</span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <StatCard icon={Activity} label="Total Requests" value={stats?.total_requests ?? "—"} />
          <StatCard icon={ShieldAlert} label="Blocked Total" value={stats?.blocked_total ?? "—"} color="text-red-400" />
          <StatCard icon={Shield} label="Block Rate" value={stats ? `${(stats.block_rate * 100).toFixed(1)}%` : "—"} color="text-orange-400" />
          <StatCard icon={Clock} label="Avg Detection" value={stats ? `${stats.avg_latency_ms}ms` : "—"} color="text-blue-400" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-xl p-5">
            <h2 className="text-sm font-medium text-zinc-400 mb-4">Requests — last 24h</h2>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={timeline}>
                <XAxis dataKey="hour" tick={{ fill: "#71717a", fontSize: 11 }} tickFormatter={(v: string) => v.slice(11, 16)} />
                <YAxis tick={{ fill: "#71717a", fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #3f3f46" }} />
                <Line type="monotone" dataKey="total" stroke="#3b82f6" dot={false} strokeWidth={2} />
                <Line type="monotone" dataKey="blocked" stroke="#ef4444" dot={false} strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
            <div className="flex gap-4 mt-2 text-xs text-zinc-500">
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-blue-500 inline-block" /> total</span>
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-red-500 inline-block" /> blocked</span>
            </div>
          </div>

          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
            <h2 className="text-sm font-medium text-zinc-400 mb-4">Attack Types</h2>
            {attackTypes.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={attackTypes} dataKey="count" nameKey="attack_type" cx="50%" cy="50%" innerRadius={50} outerRadius={80}>
                    {attackTypes.map((entry) => (
                      <Cell key={entry.attack_type} fill={ATTACK_COLORS[entry.attack_type] ?? "#6b7280"} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #3f3f46" }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[200px] flex items-center justify-center text-zinc-600 text-sm">No attacks blocked yet</div>
            )}
          </div>
        </div>

        <div className="mt-6 bg-zinc-900 border border-zinc-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-zinc-400 mb-4">Live Feed</h2>
          {liveEvents.length === 0 ? (
            <p className="text-zinc-600 text-sm">Waiting for events...</p>
          ) : (
            <div className="space-y-2">
              {liveEvents.map((e) => (
                <div key={e.id} className="flex items-center gap-3 text-sm py-2 border-b border-zinc-800 last:border-0">
                  <span className="text-zinc-500 w-36 shrink-0 font-mono text-xs">{e.timestamp.slice(11, 19)}</span>
                  <AttackBadge type={e.attack_type} />
                  <span className="text-zinc-400 text-xs">{(e.confidence * 100).toFixed(0)}% conf</span>
                  <span className="ml-auto text-xs">
                    {e.blocked ? <span className="text-red-400">BLOCKED</span> : <span className="text-zinc-500">passed</span>}
                  </span>
                  <span className="text-zinc-600 text-xs">L{e.layer_triggered}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
