"use client";

import { useTheme } from "next-themes";
import { Moon, Sun } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

/**
 * Light/dark toggle.
 *
 * Nothing here is derived from the theme during render, which is what makes it
 * hydration-safe: both icons are always in the markup and CSS shows the right
 * one via the `dark` variant, so the server and the client emit identical HTML
 * and the correct icon is on screen in the first frame rather than after an
 * effect runs. The label is deliberately state-independent -- "Toggle theme"
 * describes the control, and a label that flipped with the theme would be one
 * more attribute to mismatch. The resolved theme is only read inside the click
 * handler, which by definition runs after hydration.
 */
export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="size-8"
          aria-label="Toggle theme"
          onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
        >
          <Moon className="size-4 dark:hidden" />
          <Sun className="hidden size-4 dark:block" />
        </Button>
      </TooltipTrigger>
      <TooltipContent>Toggle theme</TooltipContent>
    </Tooltip>
  );
}
