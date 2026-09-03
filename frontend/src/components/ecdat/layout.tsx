/**
 * Page and section chrome.
 *
 * Every screen uses the same header rhythm and the same section framing, so the
 * product reads as one system rather than a set of separately-styled pages.
 */

import type { ReactNode } from "react";

import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Info } from "lucide-react";

/**
 * Screen header. `question` is the one thing this screen answers (§32) and is
 * rendered as the subtitle -- the product story is stated on the screen itself,
 * not just in the pitch.
 */
export function PageHeader({
  title,
  question,
  description,
  actions,
  className,
}: {
  title: string;
  question?: string;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between",
        className,
      )}
    >
      <div className="min-w-0 space-y-1">
        <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">{title}</h1>
        {question ? (
          <p className="text-muted-foreground text-sm">{question}</p>
        ) : null}
        {description ? (
          <div className="text-muted-foreground max-w-3xl text-xs leading-relaxed">
            {description}
          </div>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** Standard page padding. One definition so screens cannot drift apart. */
export function PageShell({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("min-w-0 space-y-6 p-4 sm:p-6", className)}>{children}</div>
  );
}

/**
 * A titled panel. `help` renders an info affordance carrying the backend's own
 * wording -- methodology text is quoted, never paraphrased into a claim ECDAT
 * did not make.
 */
export function Section({
  title,
  description,
  help,
  actions,
  children,
  className,
  contentClassName,
  bare = false,
}: {
  title: string;
  description?: ReactNode;
  help?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
  /** Drop the card padding: for tables and graphs that manage their own. */
  bare?: boolean;
}) {
  return (
    <Card className={cn("min-w-0 gap-0 overflow-hidden py-0", className)}>
      <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0 border-b px-4 py-3">
        <div className="min-w-0 space-y-0.5">
          <CardTitle className="flex items-center gap-1.5 text-sm font-semibold">
            <span className="truncate">{title}</span>
            {help ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    aria-label={`About ${title}`}
                    className="text-muted-foreground hover:text-foreground shrink-0 transition-colors"
                  >
                    <Info className="size-3.5" />
                  </button>
                </TooltipTrigger>
                <TooltipContent className="max-w-80 text-xs leading-relaxed">
                  {help}
                </TooltipContent>
              </Tooltip>
            ) : null}
          </CardTitle>
          {description ? (
            <p className="text-muted-foreground text-xs">{description}</p>
          ) : null}
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
      </CardHeader>
      <CardContent className={cn(bare ? "p-0" : "p-4", "min-w-0", contentClassName)}>
        {children}
      </CardContent>
    </Card>
  );
}

/**
 * A labelled value. The workhorse of the detail screens: a label, a value, and
 * optionally the provenance of that value so a default never reads as a fact.
 */
export function Field({
  label,
  value,
  hint,
  badge,
  mono = false,
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  badge?: ReactNode;
  mono?: boolean;
  className?: string;
}) {
  const empty = value === null || value === undefined || value === "";
  return (
    <div className={cn("min-w-0 space-y-1", className)}>
      <div className="flex items-center gap-1.5">
        <p className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
          {label}
        </p>
        {badge}
      </div>
      <div
        className={cn(
          "text-sm leading-snug break-words",
          mono && "font-mono text-[13px]",
          empty && "text-muted-foreground",
        )}
      >
        {empty ? "—" : value}
      </div>
      {hint ? <p className="text-muted-foreground text-[11px]">{hint}</p> : null}
    </div>
  );
}

/** Responsive field grid. Two columns at tablet, three or four on desktop. */
export function FieldGrid({
  children,
  columns = 3,
  className,
}: {
  children: ReactNode;
  columns?: 2 | 3 | 4;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "grid gap-x-6 gap-y-4 sm:grid-cols-2",
        columns === 3 && "lg:grid-cols-3",
        columns === 4 && "lg:grid-cols-4",
        className,
      )}
    >
      {children}
    </div>
  );
}

/**
 * A verbatim quote of backend methodology or policy wording. Visually distinct
 * from ECDAT's own UI copy so a judge can tell which sentences are the
 * engine's own claims.
 */
export function MethodNote({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <p
      className={cn(
        "text-muted-foreground border-l-2 pl-3 text-xs leading-relaxed",
        className,
      )}
    >
      {children}
    </p>
  );
}
