/**
 * Application providers.
 *
 * One client boundary at the root of the tree so every screen below can be a
 * server component by default and only opt into interactivity where needed.
 */

"use client";

import { useState, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";

import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";

export function Providers({ children }: { children: ReactNode }) {
  // Created once per browser session. A module-level client would be shared
  // across requests during SSR and leak one user's cache into another's.
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // Analytical results only change when a scan is re-run, and a scan
            // invalidates everything explicitly. Long staleness therefore costs
            // nothing and keeps navigation between screens instant.
            staleTime: 5 * 60 * 1000,
            gcTime: 30 * 60 * 1000,
            refetchOnWindowFocus: false,
            retry: 1,
          },
        },
      }),
  );

  return (
    <QueryClientProvider client={queryClient}>
      {/*
        Light is the default, and deliberately so: this is an enterprise security
        console, and the light surface is the one the design system was specified
        against (white cards on a light cool-gray page).

        `enableSystem={false}` means a machine set to dark still opens light, so
        the product looks the same on any reviewer's laptop without anyone having
        to touch the toggle. Dark stays fully styled behind the toggle.

        `storageKey` is namespaced. next-themes reads the stored preference before
        React paints, so a value left behind by an earlier build -- when dark was
        the default -- would keep overriding it; the new key starts everyone on
        light and then persists whatever they choose.

        No flash of dark: with light as the default there is no `dark` class in
        the server HTML and none injected before paint, so the first frame is
        already the final one.
      */}
      <ThemeProvider
        attribute="class"
        defaultTheme="light"
        enableSystem={false}
        storageKey="ecdat-theme"
        disableTransitionOnChange
      >
        <TooltipProvider delayDuration={200}>
          {children}
          <Toaster position="bottom-right" richColors closeButton />
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
