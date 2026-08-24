import { cloneElement, isValidElement } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";

/* Smooth skeleton→content swap, shared by every list/detail view.
 *
 * The two halves are separate components so each page can keep its own
 * markup while the timing lives in one place. `mode='wait'` holds the
 * incoming branch until the skeleton has finished fading, which is what
 * stops the swap from reading as an instant cut.
 *
 * `settled` (useQuery's `contentEntered`) is true when the query already
 * had cached data at mount - an SPA navigation. Animating that would fade
 * content the user has effectively already seen, so it renders at rest.
 */

const SKELETON_EXIT_S = 0.5;
const CONTENT_ENTER_S = 0.3;

/* AnimatePresence diffs its *direct* children by `child.key`, so a key set
 * on the inner motion element inside QuerySkeleton/QueryContent never reaches
 * it - both branches read as key "", the outgoing one is never seen as
 * exiting, and the swap becomes the instant cut we're trying to avoid.
 * Rather than make all ~16 call sites remember a key, stamp one here from the
 * branch's component type. An explicit key at the call site still wins, which
 * is what the empty-state and error branches rely on. */
function withBranchKey(child) {
  if (!isValidElement(child)) return child;
  if (child.key != null) return child;
  const key =
    child.type === QuerySkeleton
      ? "skeleton"
      : child.type === QueryContent
        ? "content"
        : "branch";
  return cloneElement(child, { key });
}

export function QuerySwap({ children }) {
  return (
    <AnimatePresence mode='wait' initial={false}>
      {Array.isArray(children)
        ? children.map(withBranchKey)
        : withBranchKey(children)}
    </AnimatePresence>
  );
}

export function QuerySkeleton({ as = "div", children, ...props }) {
  const reduced = useReducedMotion();
  const Tag = motion[as];
  return (
    <Tag
      animate={{ opacity: 1 }}
      exit={{ opacity: reduced ? 1 : 0.2 }}
      transition={{ duration: reduced ? 0 : SKELETON_EXIT_S, ease: "easeOut" }}
      role='status'
      {...props}
    >
      {children}
    </Tag>
  );
}

export function QueryContent({ as = "div", settled = false, children, ...props }) {
  const reduced = useReducedMotion();
  const Tag = motion[as];
  const still = settled || reduced;
  return (
    <Tag
      initial={{ opacity: still ? 1 : 0.4 }}
      animate={{ opacity: 1 }}
      transition={{ duration: still ? 0 : CONTENT_ENTER_S, ease: "easeIn" }}
      {...props}
    >
      {children}
    </Tag>
  );
}

export default QuerySwap;
