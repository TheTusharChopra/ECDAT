/**
 * Viewport-width predicate for the sidebar's mobile behaviour.
 *
 * `useSyncExternalStore` rather than state-plus-effect: `matchMedia` *is* an
 * external store, and subscribing to it this way gives a correct value on the
 * first client render instead of `false` followed by a second render. The server
 * snapshot is `false` -- there is no viewport during SSR, and the desktop layout
 * is the right thing to send.
 */
import * as React from "react"

const MOBILE_BREAKPOINT = 768
const QUERY = `(max-width: ${MOBILE_BREAKPOINT - 1}px)`

function subscribe(onChange: () => void) {
  const mql = window.matchMedia(QUERY)
  mql.addEventListener("change", onChange)
  return () => mql.removeEventListener("change", onChange)
}

export function useIsMobile() {
  return React.useSyncExternalStore(
    subscribe,
    () => window.matchMedia(QUERY).matches,
    () => false,
  )
}
