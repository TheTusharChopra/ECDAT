/**
 * Navigation registry.
 *
 * One declaration of the product's screens, consumed by the sidebar, the
 * breadcrumb trail and the command palette. Adding a screen in one place keeps
 * all three in agreement.
 *
 * The `question` field is the screen's job in the product story (§32): each
 * view answers exactly one question about the estate, and the sidebar says so.
 */

import {
  ArrowRightLeft,
  Boxes,
  FileJson2,
  LayoutDashboard,
  ListChecks,
  Network,
  Radar,
  Route,
  Settings,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  title: string;
  href: string;
  icon: LucideIcon;
  /** The single question this screen answers. Shown as sidebar tooltip help. */
  question: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Estate",
    items: [
      {
        title: "Overview",
        href: "/",
        icon: LayoutDashboard,
        question: "What cryptography exists across the estate?",
      },
      {
        title: "Inventory",
        href: "/inventory",
        icon: Boxes,
        question: "Where is each cryptographic asset?",
      },
      {
        title: "Asset Graph",
        href: "/graph",
        icon: Network,
        question: "What depends on this asset?",
      },
    ],
  },
  {
    label: "Analysis",
    items: [
      {
        title: "Risk & Quantum",
        href: "/risk",
        icon: ShieldAlert,
        question: "Why does this asset matter, on both axes?",
      },
      {
        title: "Migration Center",
        href: "/migration",
        icon: ArrowRightLeft,
        question: "What should we do about it?",
      },
      {
        title: "Roadmap",
        href: "/roadmap",
        icon: Route,
        question: "What happens next, and in what order?",
      },
    ],
  },
  {
    label: "Output",
    items: [
      {
        title: "Reports / CBOM",
        href: "/reports",
        icon: FileJson2,
        question: "What can we hand to an auditor or a tool?",
      },
      {
        title: "Remediation",
        href: "/remediation",
        icon: ListChecks,
        question: "What is the tracked state of each change?",
      },
    ],
  },
];

export const SCAN_ITEM: NavItem = {
  title: "Scan",
  href: "/scan",
  icon: Radar,
  question: "Discover cryptography across a target estate.",
};

export const SETTINGS_ITEM: NavItem = {
  title: "Settings",
  href: "/settings",
  icon: Settings,
  question: "Policy, threat horizon and API connection.",
};

export const ALL_NAV_ITEMS: NavItem[] = [
  ...NAV_GROUPS.flatMap((group) => group.items),
  SCAN_ITEM,
  SETTINGS_ITEM,
];

/** Human label for a path segment, for the breadcrumb trail. */
export const SEGMENT_LABELS: Record<string, string> = {
  inventory: "Inventory",
  graph: "Asset Graph",
  risk: "Risk & Quantum",
  migration: "Migration Center",
  roadmap: "Roadmap",
  reports: "Reports / CBOM",
  remediation: "Remediation",
  settings: "Settings",
  scan: "Scan",
  assets: "Inventory",
};

/**
 * Which sidebar entry should read as active for a given pathname. An asset
 * detail page lives under `/assets/…` but belongs to Inventory.
 */
export function activeNavHref(pathname: string): string {
  if (pathname === "/") return "/";
  if (pathname.startsWith("/assets")) return "/inventory";
  const top = `/${pathname.split("/").filter(Boolean)[0] ?? ""}`;
  return ALL_NAV_ITEMS.some((item) => item.href === top) ? top : pathname;
}
