/**
 * Placeholder for a screen that is declared in the navigation registry but not
 * yet built.
 *
 * These exist for one reason: the sidebar, the command palette and the
 * dashboard's click-throughs all link to these routes, and in a production build
 * `next/link` prefetches every one of them. A route with no page 404s on
 * prefetch -- fourteen console errors on the dashboard alone, before the user
 * clicks anything. So the route has to resolve.
 *
 * It says plainly that the screen is not implemented and names the endpoint that
 * will drive it, so the state of the product is legible rather than implied. It
 * deliberately renders no numbers, no charts and no sample rows: an empty screen
 * that admits it is empty is honest, and a screen with invented figures on it
 * would not be (§36).
 */

import type { ReactNode } from "react";
import Link from "next/link";
import { Construction } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader, PageShell, Section } from "@/components/ecdat/layout";

export function PlannedScreen({
  title,
  question,
  /** Endpoints already served by the API that this screen will read. */
  endpoints,
  /** What the finished screen will show. Description of intent, not of data. */
  children,
}: {
  title: string;
  question: string;
  endpoints: string[];
  children?: ReactNode;
}) {
  return (
    <PageShell>
      <PageHeader
        title={title}
        question={question}
        actions={
          <Badge variant="outline" className="gap-1.5 text-[11px]">
            <Construction className="size-3" />
            Not yet implemented
          </Badge>
        }
      />

      <Section
        title="This screen is not built yet"
        description="Placeholder route. Nothing on this page is analysis output."
      >
        <div className="space-y-4 text-sm leading-relaxed">
          {children ? <div className="text-muted-foreground max-w-2xl">{children}</div> : null}

          <div className="space-y-2">
            <p className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
              Backend data this screen will read
            </p>
            <ul className="space-y-1">
              {endpoints.map((endpoint) => (
                <li key={endpoint} className="font-mono text-[13px]">
                  {endpoint}
                </li>
              ))}
            </ul>
            <p className="text-muted-foreground text-xs">
              These endpoints are implemented and serving live results already — the
              analysis exists, the visualisation does not.
            </p>
          </div>

          <Button asChild variant="outline" size="sm">
            <Link href="/">Back to overview</Link>
          </Button>
        </div>
      </Section>
    </PageShell>
  );
}
