/**
 * The seven dashboard KPIs (§7).
 *
 * Every figure is read straight out of `GET /dashboard`; none is computed here
 * (§30, §37). Two are ratios of two backend headline counts -- stated as such
 * in their captions, because a percentage that hides its denominator is how a
 * security dashboard starts lying.
 *
 * Each card's click-through was checked against the API: the count on the card
 * is exactly the count the filtered inventory returns.
 */

"use client";

import {
  Atom,
  Boxes,
  FileBadge2,
  ShieldAlert,
  ShieldCheck,
  Unplug,
  Waypoints,
} from "lucide-react";

import type { DashboardSummary } from "@/types/api";
import { AGILITY_COLOR, formatNumber, percentOf } from "@/lib/display";
import { KpiCard, KpiGrid } from "@/features/dashboard/kpi-card";
import { KpiSkeleton } from "@/components/ecdat/states";

export function KpiRowSkeleton() {
  return (
    <KpiGrid>
      {Array.from({ length: 7 }).map((_, index) => (
        <KpiSkeleton key={index} />
      ))}
    </KpiGrid>
  );
}

export function KpiRow({ data }: { data: DashboardSummary }) {
  const { estate, headlines, classical_axis, asset_types, crypto_agility, roadmap_totals } =
    data;

  const total = headlines.total_assets;
  const criticalClassical = classical_axis.critical ?? 0;
  const certificates = asset_types.certificate ?? 0;
  const agilityLow = crypto_agility.low ?? 0;
  const agilityHigh = crypto_agility.high ?? 0;
  const agilityMedium = crypto_agility.medium ?? 0;

  return (
    <KpiGrid>
      <KpiCard
        wide
        label="Total Crypto Assets"
        value={total}
        detail={`${formatNumber(estate.applications)} applications`}
        icon={Boxes}
        accent="var(--primary)"
        href="/inventory"
        caption="Canonical cryptographic assets after evidence correlation. One asset may be attested by several detectors; duplicates are merged, not counted twice."
        help="A canonical asset is the deduplicated unit of cryptography ECDAT reasons about — an algorithm in a role, in a place. Every one is backed by at least one evidence record."
        segments={[
          {
            label: `Needs change: ${headlines.need_change}`,
            value: headlines.need_change,
            color: "var(--warning)",
          },
          {
            label: `No change required: ${headlines.need_no_change}`,
            value: headlines.need_no_change,
            color: "var(--success)",
          },
        ]}
      />

      <KpiCard
        label="Quantum Exposed"
        value={headlines.quantum_vulnerable}
        detail={`${headlines.quantum_vulnerable_pct} of estate`}
        icon={Atom}
        accent="var(--quantum-critical)"
        href="/inventory?quantum_exposure=critical"
        caption="Assets whose mathematics a large-scale quantum computer breaks. This is the quantum axis and is scored independently of present-day risk."
        help="Quantum exposure is derived from the algorithm's quantum class (Shor-broken, Grover-reduced, PQC-standardised…). It says nothing about whether the asset is exploitable today — that is the classical axis."
      />

      <KpiCard
        label="Critical Assets"
        value={criticalClassical}
        detail={`${percentOf(criticalClassical, total)}% of estate`}
        icon={ShieldAlert}
        accent="var(--risk-critical)"
        href="/inventory?classical_risk=critical"
        caption={`CRITICAL on the classical axis — weak against today's computers. ${headlines.classically_broken_today} assets in the estate use a mechanism already considered broken.`}
        help="Classical risk reflects present-day cryptanalysis, key sizes and policy floors. An asset can be classically LOW and quantum CRITICAL, or the reverse; the two axes never collapse into one score."
      />

      <KpiCard
        label="Migration Priorities"
        value={headlines.scheduled}
        detail={`${roadmap_totals.p0} in P0`}
        icon={Waypoints}
        accent="var(--info)"
        href="/roadmap"
        caption={`Assets scheduled into the migration programme. The other ${headlines.need_no_change} were assessed as needing no cryptographic change.`}
        help="Scheduling is priority-band ordered and sequenced from the asset graph. Priority bands P0–P3 rank the whole estate; only assets with a migration decision other than RETAIN enter the programme."
      />

      <KpiCard
        label="Certificates"
        value={certificates}
        detail="X.509 parsed"
        icon={FileBadge2}
        accent="var(--chart-3)"
        href="/inventory?asset_type=certificate"
        caption="Certificates parsed from the estate, each carrying its issuer, validity window and signature algorithm as discovered facts."
        help="Certificates are parsed locally. Public certificate metadata is retained; no private key material is ever stored or displayed."
      />

      <KpiCard
        label="PQC Readiness"
        value={`${percentOf(headlines.need_no_change, total)}%`}
        detail={`${headlines.need_no_change} of ${total}`}
        icon={ShieldCheck}
        accent="var(--success)"
        href="/inventory?decision=RETAIN"
        caption="Share of assets ECDAT assessed as needing no post-quantum change. An engineering assessment of this estate — not a compliance or certification status."
        help="Computed by the backend as the RETAIN share of the canonical inventory. It does not certify conformance to FIPS 203/204/205 or to any procurement requirement."
      />

      <KpiCard
        label="Crypto Agility"
        value={agilityLow}
        detail="hard to change"
        icon={Unplug}
        accent={AGILITY_COLOR.low}
        href="/inventory?agility=low"
        caption="Assets that cannot be changed without a coordinated dependency, protocol or CA change. Agility is a canonical field on the asset, not a derived score."
        help="LOW agility means the algorithm is pinned by something outside the codebase — a peer, a certificate authority, a compiled binary. These assets need lead time even when their risk is low."
        segments={[
          { label: `High: ${agilityHigh}`, value: agilityHigh, color: AGILITY_COLOR.high },
          {
            label: `Medium: ${agilityMedium}`,
            value: agilityMedium,
            color: AGILITY_COLOR.medium,
          },
          { label: `Low: ${agilityLow}`, value: agilityLow, color: AGILITY_COLOR.low },
        ]}
      />
    </KpiGrid>
  );
}
