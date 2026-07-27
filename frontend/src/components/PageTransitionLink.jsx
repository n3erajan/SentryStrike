import { flushSync } from "react-dom";
import { Link, useNavigate } from "react-router-dom";

let transitionSequence = 0;

const PUBLIC_PAGE_ORDER = new Map([
  ["/", 0],
  ["/login", 1],
  ["/request-access", 2],
  ["/register", 2],
]);

function transitionDirection(targetHref) {
  const currentPath = new URL(window.location.href).pathname;
  const targetPath = new URL(targetHref).pathname;
  const currentPosition = PUBLIC_PAGE_ORDER.get(currentPath);
  const targetPosition = PUBLIC_PAGE_ORDER.get(targetPath);

  if (currentPosition === undefined || targetPosition === undefined) {
    return "forward";
  }
  return targetPosition < currentPosition ? "back" : "forward";
}

function isPlainLeftClick(event) {
  return (
    event.button === 0 &&
    !event.metaKey &&
    !event.ctrlKey &&
    !event.shiftKey &&
    !event.altKey
  );
}

export default function PageTransitionLink({
  to,
  replace,
  state,
  preventScrollReset,
  relative,
  target,
  onClick,
  ...props
}) {
  const navigate = useNavigate();

  function handleClick(event) {
    onClick?.(event);

    const reducedMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;
    if (
      event.defaultPrevented ||
      !isPlainLeftClick(event) ||
      target === "_blank" ||
      !document.startViewTransition ||
      reducedMotion
    ) {
      return;
    }

    event.preventDefault();
    const root = document.documentElement;
    const direction = transitionDirection(event.currentTarget.href);
    const sequence = ++transitionSequence;
    root.dataset.pageTransition = direction;

    const transition = document.startViewTransition(() => {
      flushSync(() => {
        navigate(to, { replace, state, preventScrollReset, relative });
      });
    });
    transition.finished.finally(() => {
      if (sequence === transitionSequence) {
        delete root.dataset.pageTransition;
      }
    });
  }

  return (
    <Link
      {...props}
      to={to}
      replace={replace}
      state={state}
      preventScrollReset={preventScrollReset}
      relative={relative}
      target={target}
      onClick={handleClick}
    />
  );
}
