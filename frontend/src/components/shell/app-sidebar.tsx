/**
 * Left navigation.
 *
 * Collapses to an icon rail (Cmd/Ctrl+B) so the graph and inventory screens can
 * use the full width on a 1366px projector. Each entry carries the question it
 * answers, shown in the collapsed tooltip -- the product story lives in the
 * navigation, not only in the documentation.
 */

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck } from "lucide-react";

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar";
import {
  NAV_GROUPS,
  SCAN_ITEM,
  SETTINGS_ITEM,
  activeNavHref,
  type NavItem,
} from "@/lib/navigation";

function NavLink({ item, active }: { item: NavItem; active: boolean }) {
  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        asChild
        isActive={active}
        tooltip={{ children: <span className="max-w-52">{item.question}</span> }}
      >
        <Link href={item.href}>
          <item.icon />
          <span>{item.title}</span>
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}

export function AppSidebar() {
  const pathname = usePathname();
  const active = activeNavHref(pathname);

  return (
    <Sidebar collapsible="icon" variant="inset">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild size="lg" tooltip="ECDAT">
              <Link href="/">
                <div className="bg-primary text-primary-foreground flex aspect-square size-8 items-center justify-center rounded-lg">
                  <ShieldCheck className="size-4.5" />
                </div>
                <div className="grid flex-1 text-left leading-tight">
                  <span className="truncate text-sm font-semibold tracking-tight">
                    ECDAT
                  </span>
                  <span className="text-muted-foreground truncate text-[11px]">
                    Cryptographic Discovery
                  </span>
                </div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent className="ecdat-scrollbar">
        {NAV_GROUPS.map((group) => (
          <SidebarGroup key={group.label}>
            <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map((item) => (
                  <NavLink key={item.href} item={item} active={active === item.href} />
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <NavLink item={SCAN_ITEM} active={active === SCAN_ITEM.href} />
          <NavLink item={SETTINGS_ITEM} active={active === SETTINGS_ITEM.href} />
        </SidebarMenu>
      </SidebarFooter>

      <SidebarRail />
    </Sidebar>
  );
}
