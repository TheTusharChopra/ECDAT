/**
 * Application shell: sidebar + top bar + page surface.
 *
 * A single client boundary for the chrome, so page content below can stay as
 * plain as it likes. The page transition is a 120ms fade with a 4px rise --
 * enough to make navigation feel deliberate, far short of animation that would
 * draw attention to itself (§24).
 */

"use client";

import type { ReactNode } from "react";
import { usePathname } from "next/navigation";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";

import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/shell/app-sidebar";
import { Topbar } from "@/components/shell/topbar";
import { CommandPalette, useCommandPalette } from "@/components/shell/command-palette";

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { open, setOpen } = useCommandPalette();
  const reduceMotion = useReducedMotion();

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset className="min-w-0 overflow-hidden">
        <Topbar onOpenSearch={() => setOpen(true)} />
        {/*
          `min-w-0` all the way down is what keeps wide tables and graphs from
          pushing the page sideways (§25: nothing may overflow horizontally).
          Wide content scrolls inside its own container instead.
        */}
        <main className="ecdat-scrollbar min-w-0 flex-1 overflow-x-hidden">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={pathname}
              initial={reduceMotion ? false : { opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.12, ease: "easeOut" }}
              className="min-w-0"
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </SidebarInset>
      <CommandPalette open={open} onOpenChange={setOpen} />
    </SidebarProvider>
  );
}
