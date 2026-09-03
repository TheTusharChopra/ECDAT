import { Suspense } from "react";

import { TableSkeleton } from "@/components/ecdat/states";
import { PageHeader, PageShell } from "@/components/ecdat/layout";
import { InventoryScreen } from "@/features/inventory/inventory-screen";

export const metadata = { title: "Inventory" };

/**
 * The screen reads its whole state from the URL, so it needs `useSearchParams`.
 * In Next 16 that bails the client tree out to the nearest Suspense boundary
 * during prerender, so the boundary is explicit and its fallback is the same
 * skeleton the screen itself uses while loading.
 */
export default function InventoryPage() {
  return (
    <Suspense fallback={<InventoryFallback />}>
      <InventoryScreen />
    </Suspense>
  );
}

function InventoryFallback() {
  return (
    <PageShell>
      <PageHeader
        title="Inventory"
        question="What cryptography exists, and what has the assessment decided about it?"
        description="Every canonical asset the scan produced, with both decision levels side by side: the migration decision, and the specific strategy recommended beneath it."
      />
      <TableSkeleton rows={12} columns={9} />
    </PageShell>
  );
}
