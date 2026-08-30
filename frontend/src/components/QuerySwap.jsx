/* Skeleton→content swap, shared by every list/detail view.
 *
 * The swap is intentionally instant. The skeleton is shown only while the
 * query is genuinely in flight; the moment data arrives, the content replaces
 * it with no fade and no artificial minimum lifespan. (The previous version
 * faded the skeleton out over 500ms via AnimatePresence `mode='wait'`, on top
 * of a min-loading floor in queryCache — both removed.)
 *
 * `QuerySkeleton` and `QueryContent` remain named wrappers so each page keeps
 * its own markup and the ~16 call sites stay unchanged. `settled` is accepted
 * for call-site compatibility and intentionally ignored now that there is no
 * entrance animation to gate.
 */

export function QuerySwap({ children }) {
  return <>{children}</>;
}

export function QuerySkeleton({ as: Tag = "div", children, ...props }) {
  return (
    <Tag role='status' {...props}>
      {children}
    </Tag>
  );
}

export function QueryContent({ as: Tag = "div", settled = false, children, ...props }) {
  void settled;
  return <Tag {...props}>{children}</Tag>;
}

export default QuerySwap;
