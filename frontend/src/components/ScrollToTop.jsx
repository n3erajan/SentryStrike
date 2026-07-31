import { useLayoutEffect } from "react";
import { useLocation, useNavigationType } from "react-router-dom";

/* Reset the window scroll on navigation.
 *
 * The document never unloads in an SPA, so `window.scrollY` carries over from
 * the previous route — clicking a footer link from the bottom of the landing
 * page drops you into the middle of the next one. BrowserRouter has no
 * built-in restoration (ScrollRestoration is data-router only), so this does
 * it here.
 *
 * Two cases deliberately keep their scroll position:
 *   - a hash target, which the browser (or the legal pages' section nav)
 *     scrolls to itself;
 *   - POP, i.e. back/forward, where the browser restores the previous offset
 *     and overwriting it would lose the reader's place.
 */
function ScrollToTop() {
  const { pathname, hash } = useLocation();
  const navigationType = useNavigationType();

  // Layout effect so the reset lands in the same frame as the new route's
  // paint; a passive effect lets the page show at the stale offset first.
  useLayoutEffect(() => {
    if (hash || navigationType === "POP") return;
    // `html` is scroll-behavior: smooth, which would otherwise animate the
    // whole way up and read as the page scrolling itself on arrival.
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
  }, [pathname, hash, navigationType]);

  return null;
}

export default ScrollToTop;
