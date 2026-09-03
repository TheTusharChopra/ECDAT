"use client";

import {
  CalendarClock,
  CheckCircle2,
  RefreshCw,
} from "lucide-react";

import { useDashboard, useHealth } from "@/lib/queries";
import { API_BASE } from "@/lib/api-client";
import { PageHeader, PageShell, Section } from "@/components/ecdat/layout";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function SettingsPage() {
  const health = useHealth();
  const dashboard = useDashboard();

  return (
    <PageShell>
      <PageHeader
        title="Settings & Policies"
        question="Which threat horizons and compliance standards govern the analysis engine?"
        description="ECDAT's analytical engine evaluates cryptographic assets against configurable compliance policies and threat horizons without synthetic data."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void health.refetch();
              void dashboard.refetch();
            }}
            disabled={health.isFetching}
          >
            <RefreshCw className={health.isFetching ? "mr-1.5 size-3.5 animate-spin" : "mr-1.5 size-3.5"} />
            Refresh
          </Button>
        }
      />

      {/* Threat Horizon Configuration */}
      <Section
        title="Active Threat Horizon (CRQC Policy Anchor)"
        description="The planning horizon used for Mosca inequality calculations (z)"
      >
        <Card className="p-5 space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex items-center gap-2">
                <CalendarClock className="size-5 text-primary" />
                <h3 className="text-lg font-bold text-foreground">
                  Target CRQC Year: {dashboard.data?.scenario.crqc_year ?? "2035"}
                </h3>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Policy Anchor: <strong>{dashboard.data?.estate.policy ?? "nist_general"}</strong>
              </p>
            </div>
            <Badge variant="outline" className="font-mono text-xs text-success border-success bg-success/10">
              Active Policy Profile
            </Badge>
          </div>

          <div className="rounded-md bg-muted/40 p-3 text-xs leading-relaxed text-muted-foreground">
            <span className="font-semibold text-foreground">Important Note on Threat Horizons: </span>
            {dashboard.data?.scenario.crqc_rationale ??
              "The CRQC year is a policy-planning horizon established by NIST and government directives, not a physics prediction. It serves as the deterministic deadline anchor for Mosca urgency calculations."}
          </div>
        </Card>
      </Section>

      {/* Available Policy Profiles */}
      <Section
        title="Available Standards & Profiles"
        description="Cryptographic policy benchmarks supported by the engine"
      >
        <div className="grid gap-4 md:grid-cols-3">
          <PolicyCard
            title="NIST General (Default)"
            code="nist_general"
            deadline="2035"
            standards={["FIPS 203 (ML-KEM)", "FIPS 204 (ML-DSA)", "SP 800-131A Rev 2"]}
            description="General commercial enterprise baseline aligned with NIST Post-Quantum Cryptography standards."
            active={dashboard.data?.estate.policy === "nist_general" || !dashboard.data?.estate.policy}
          />
          <PolicyCard
            title="NSA CNSA 2.0"
            code="nsa_cnsa2"
            deadline="2033"
            standards={["CNSA 2.0", "AES-256", "ML-KEM-1024", "ML-DSA-87"]}
            description="Commercial National Security Algorithm Suite 2.0 for high-assurance and defense-adjacent environments."
            active={dashboard.data?.estate.policy === "nsa_cnsa2"}
          />
          <PolicyCard
            title="High Assurance Hybrid"
            code="high_assurance_hybrid"
            deadline="2030"
            standards={["Hybrid PQ/T Only", "IETF Drafts", "Strict FIPS"]}
            description="Accelerated deadline requiring PQ/T hybrid key establishment across all external and internal endpoints."
            active={dashboard.data?.estate.policy === "high_assurance_hybrid"}
          />
        </div>
      </Section>

      {/* Backend Health & Topology */}
      <Section
        title="Engine Topology & Connectivity"
        description="Status of the live ECDAT Python analysis backend"
      >
        <Card className="p-4">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 text-xs">
            <div className="space-y-1">
              <span className="text-muted-foreground">Backend API URL</span>
              <p className="font-mono font-medium text-foreground">{API_BASE}</p>
            </div>
            <div className="space-y-1">
              <span className="text-muted-foreground">API Status</span>
              <div className="flex items-center gap-1.5 font-medium text-success">
                <CheckCircle2 className="size-3.5" />
                {health.data?.status ?? "online"} (v{health.data?.api_version ?? "1.0.0"})
              </div>
            </div>
            <div className="space-y-1">
              <span className="text-muted-foreground">Active Scan ID</span>
              <p className="font-mono font-medium text-foreground">{health.data?.scan_id ?? "scan-loaded"}</p>
            </div>
            <div className="space-y-1">
              <span className="text-muted-foreground">Loaded Inventory</span>
              <p className="font-semibold text-foreground">{health.data?.assets ?? 0} Assets</p>
            </div>
          </div>
        </Card>
      </Section>
    </PageShell>
  );
}

function PolicyCard({
  title,
  code,
  deadline,
  standards,
  description,
  active,
}: {
  title: string;
  code: string;
  deadline: string;
  standards: string[];
  description: string;
  active: boolean;
}) {
  return (
    <Card className={`p-4 flex flex-col justify-between ${active ? "border-primary shadow-xs" : ""}`}>
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Badge variant={active ? "default" : "outline"} className="font-mono text-[10px]">
            {code}
          </Badge>
          <span className="font-mono text-xs text-muted-foreground">Target: {deadline}</span>
        </div>
        <h4 className="font-bold text-sm text-foreground">{title}</h4>
        <p className="text-xs text-muted-foreground leading-relaxed">{description}</p>
        <div className="pt-2">
          <span className="text-[10px] font-semibold uppercase text-muted-foreground">Key Standards:</span>
          <div className="mt-1 flex flex-wrap gap-1">
            {standards.map((s) => (
              <Badge key={s} variant="secondary" className="text-[10px]">
                {s}
              </Badge>
            ))}
          </div>
        </div>
      </div>
    </Card>
  );
}
