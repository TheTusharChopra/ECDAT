/**
 * "Run the demo scan" — the one action that turns an empty backend into a
 * populated one.
 *
 * The API starts with no scan loaded, and every screen is empty until one exists
 * (§2). Rather than each screen inventing its own recovery, they all render this:
 * a real `POST /scan` against the bundled demo estate, which then invalidates
 * every query so the screen the operator is already looking at fills in.
 *
 * The scan is synchronous on the backend, so there is nothing to poll and no
 * percentage to show. The button says what it is doing and waits.
 */

"use client";

import { useRouter } from "next/navigation";
import Link from "next/link";
import { Loader2, Radar } from "lucide-react";
import { toast } from "sonner";

import { useScan } from "@/lib/queries";
import { formatNumber } from "@/lib/display";
import { Button } from "@/components/ui/button";

export function RunDemoScanButton({
  size = "sm",
  variant = "default",
  /** Navigate to the scan screen when it finishes, instead of staying put. */
  navigateOnSuccess = false,
  label = "Run demo scan",
}: {
  size?: "sm" | "default" | "lg";
  variant?: "default" | "outline" | "secondary" | "ghost";
  navigateOnSuccess?: boolean;
  label?: string;
}) {
  const scan = useScan();
  const router = useRouter();

  return (
    <Button
      size={size}
      variant={variant}
      disabled={scan.isPending}
      onClick={() =>
        scan.mutate(
          { demo: true },
          {
            onSuccess: (result) => {
              toast.success("Demo scan complete", {
                description: `${formatNumber(result.assets)} cryptographic assets across ${formatNumber(
                  result.applications,
                )} applications. Scan ${result.scan_id}.`,
              });
              if (navigateOnSuccess) router.push("/scan");
            },
            onError: (error) => {
              toast.error("Scan failed", { description: error.message });
            },
          },
        )
      }
    >
      {scan.isPending ? (
        <>
          <Loader2 className="animate-spin" />
          Scanning the demo estate…
        </>
      ) : (
        <>
          <Radar />
          {label}
        </>
      )}
    </Button>
  );
}

/**
 * The pair of actions offered whenever a screen has no scan to show: run the
 * bundled demo estate right here, or go to the scan screen to choose a target.
 */
export function NoScanActions() {
  return (
    <div className="flex flex-wrap items-center justify-center gap-2">
      <RunDemoScanButton />
      <Button size="sm" variant="outline" asChild>
        <Link href="/scan">Scan options</Link>
      </Button>
    </div>
  );
}
