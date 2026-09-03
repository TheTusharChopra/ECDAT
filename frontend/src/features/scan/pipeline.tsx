/**
 * The ECDAT analysis pipeline, shown as what the scan performs.
 *
 * This is the one component on the page most likely to be mistaken for
 * something it is not, so the honesty rules are worth stating outright.
 *
 * `POST /scan` is synchronous. The engine emits progress events internally, but
 * they arrive bundled with the finished response -- the last one, always
 * `stage: "complete"`. There is no streaming endpoint, so the frontend cannot
 * know which stage is executing at any moment and must not imply that it does
 * (§3). Consequently:
 *
 *  - While the scan runs, every stage gets the SAME treatment. Nothing is shown
 *    as finished and nothing as "current", because either claim would be
 *    invented. One indeterminate sweep says work is in flight.
 *  - No percentage appears anywhere in this component. Not per stage, not
 *    overall.
 *  - Only on completion are the stages marked done, and only because the
 *    backend's own terminal progress event says the pipeline finished. That
 *    event is quoted on the card so the claim is traceable.
 *
 * The stage names describe the frozen architecture. They are a legend for the
 * analysis, not a measurement of it.
 */

"use client";

import { motion, useReducedMotion } from "motion/react";
import {
  Check,
  FileSearch,
  GitMerge,
  Layers,
  Radar,
  Route,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";

import { cn } from "@/lib/utils";

export type PipelinePhase = "idle" | "running" | "complete";

interface Stage {
  step: string;
  title: string;
  /** What the backend module actually does at this stage. */
  detail: string;
  icon: LucideIcon;
}

/**
 * The frozen pipeline. Wording tracks the architecture, not the UI: evidence is
 * correlated before a canonical asset exists, the two risk axes are assessed
 * together but never merged, and impact and roadmap are derived last.
 */
const STAGES: readonly Stage[] = [
  {
    step: "01",
    title: "Discovery",
    detail: "Detectors walk repositories, certificates, containers and binaries.",
    icon: Radar,
  },
  {
    step: "02",
    title: "Evidence correlation",
    detail: "Raw detections are matched and deduplicated into evidence records.",
    icon: FileSearch,
  },
  {
    step: "03",
    title: "Canonical asset modeling",
    detail: "One canonical cryptographic asset per real thing, with its graph.",
    icon: Layers,
  },
  {
    step: "04",
    title: "Classical + quantum assessment",
    detail: "Two independent axes, plus Mosca timing against the threat horizon.",
    icon: ShieldAlert,
  },
  {
    step: "05",
    title: "Migration decision",
    detail: "One of five decisions, and the standards-grounded strategy beneath it.",
    icon: GitMerge,
  },
  {
    step: "06",
    title: "Impact + roadmap",
    detail: "Graph-derived blast radius, sequenced into phases and priority bands.",
    icon: Route,
  },
];

export function PipelineStages({
  phase,
  className,
}: {
  phase: PipelinePhase;
  className?: string;
}) {
  return (
    <div className={cn("min-w-0 space-y-2.5", className)}>
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {STAGES.map((stage, index) => (
          <StageCard key={stage.step} stage={stage} phase={phase} index={index} />
        ))}
      </div>
      <p className="text-muted-foreground text-[11px] leading-relaxed">
        {phase === "complete"
          ? "These six stages are what the scan ran. The API returned once all of them had finished."
          : phase === "running"
            ? "ECDAT runs these six stages in a single synchronous call. This is what is executing — not how far through it is. The API reports no intermediate progress, so none is shown."
            : "These six stages describe what the analysis performs. They are a description of the pipeline, not a live progress readout."}
      </p>
    </div>
  );
}

function StageCard({
  stage,
  phase,
  index,
}: {
  stage: Stage;
  phase: PipelinePhase;
  index: number;
}) {
  const reduceMotion = useReducedMotion();
  const Icon = stage.icon;
  const running = phase === "running";
  const done = phase === "complete";

  return (
    <div
      className={cn(
        "bg-card relative flex min-w-0 gap-2.5 overflow-hidden rounded-lg border p-2.5 transition-colors",
        running && "border-primary/35 bg-primary/[0.03]",
        done && "border-success/30",
      )}
    >
      {/*
        The indeterminate sweep. Identical delay handling for every card and no
        per-stage state: it says "running", nothing more. Suppressed entirely
        when the viewer has asked for reduced motion, leaving the static tint.
      */}
      {running && !reduceMotion ? (
        <motion.span
          aria-hidden
          className="from-primary/0 via-primary/12 to-primary/0 pointer-events-none absolute inset-y-0 -left-1/3 w-1/3 bg-gradient-to-r"
          initial={{ x: 0 }}
          animate={{ x: ["0%", "400%"] }}
          transition={{
            duration: 1.6,
            repeat: Infinity,
            ease: "linear",
            delay: index * 0.08,
          }}
        />
      ) : null}

      <span
        aria-hidden
        className={cn(
          "relative grid size-7 shrink-0 place-items-center rounded-md transition-colors",
          done
            ? "bg-success/12 text-success"
            : running
              ? "bg-primary/12 text-primary"
              : "bg-muted text-muted-foreground",
        )}
      >
        {done ? <Check className="size-4" /> : <Icon className="size-4" />}
      </span>

      <div className="relative min-w-0 space-y-0.5">
        <p className="flex items-baseline gap-1.5">
          <span className="ecdat-numeric text-muted-foreground text-[10px] tracking-wider">
            {stage.step}
          </span>
          <span className="truncate text-[12.5px] font-medium">{stage.title}</span>
        </p>
        <p className="text-muted-foreground text-[11px] leading-snug">{stage.detail}</p>
      </div>
    </div>
  );
}
