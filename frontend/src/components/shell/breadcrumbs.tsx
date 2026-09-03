/**
 * Breadcrumb trail.
 *
 * Derived from the pathname against the navigation registry. On an asset detail
 * route the asset's name is read from the query cache, which the detail page has
 * already populated -- so no extra request is made to render a label.
 */

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Fragment } from "react";

import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { SEGMENT_LABELS } from "@/lib/navigation";
import { useAsset } from "@/lib/queries";

export function Breadcrumbs() {
  const pathname = usePathname();
  const segments = pathname.split("/").filter(Boolean);

  const isAssetRoute = segments[0] === "assets" && Boolean(segments[1]);
  const assetId = isAssetRoute ? decodeURIComponent(segments[1]) : "";
  // Served from cache on the detail page; the route guard means it only runs on
  // an asset URL in the first place.
  const { data: assetData } = useAsset(assetId, isAssetRoute);

  const crumbs: { label: string; href?: string }[] = [{ label: "ECDAT", href: "/" }];

  if (segments.length === 0) {
    crumbs.push({ label: "Overview" });
  } else if (isAssetRoute) {
    crumbs.push({ label: "Inventory", href: "/inventory" });
    crumbs.push({ label: assetData?.asset.asset_name ?? assetId });
  } else {
    segments.forEach((segment, index) => {
      const label = SEGMENT_LABELS[segment] ?? segment;
      const isLast = index === segments.length - 1;
      crumbs.push({
        label,
        href: isLast ? undefined : `/${segments.slice(0, index + 1).join("/")}`,
      });
    });
  }

  return (
    <Breadcrumb>
      <BreadcrumbList className="gap-1 sm:gap-1.5">
        {crumbs.map((crumb, index) => (
          // The separator is a sibling of the item, not a child: both render as
          // <li>, and an <li> inside an <li> is invalid HTML that React reports
          // as a hydration mismatch.
          <Fragment key={`${crumb.label}-${index}`}>
            <BreadcrumbItem>
              {crumb.href ? (
                <BreadcrumbLink asChild className="text-xs">
                  <Link href={crumb.href}>{crumb.label}</Link>
                </BreadcrumbLink>
              ) : (
                <BreadcrumbPage className="max-w-[22rem] truncate text-xs font-medium">
                  {crumb.label}
                </BreadcrumbPage>
              )}
            </BreadcrumbItem>
            {index < crumbs.length - 1 ? <BreadcrumbSeparator /> : null}
          </Fragment>
        ))}
      </BreadcrumbList>
    </Breadcrumb>
  );
}
