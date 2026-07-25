import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";

export default function Tooltip({ children, label, side = "bottom" }) {
  const root = useRef(null);
  const popup = useRef(null);
  const timer = useRef(null);
  const tooltipId = useId();
  const [show, setShow] = useState(false);
  const [position, setPosition] = useState({ left: 0, top: 0, side });

  function enter() {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setShow(true), 350);
  }

  function leave() {
    clearTimeout(timer.current);
    setShow(false);
  }

  useEffect(() => () => clearTimeout(timer.current), []);

  useLayoutEffect(() => {
    if (!show) return undefined;

    function updatePosition() {
      if (!root.current || !popup.current) return;
      const anchor = root.current.getBoundingClientRect();
      const tip = popup.current.getBoundingClientRect();
      const gap = 8;
      const edge = 8;
      let resolvedSide = side;

      if (side === "bottom" && anchor.bottom + gap + tip.height > window.innerHeight - edge)
        resolvedSide = "top";
      else if (side === "top" && anchor.top - gap - tip.height < edge)
        resolvedSide = "bottom";
      else if (side === "right" && anchor.right + gap + tip.width > window.innerWidth - edge)
        resolvedSide = "left";
      else if (side === "left" && anchor.left - gap - tip.width < edge)
        resolvedSide = "right";

      let left = anchor.left + (anchor.width - tip.width) / 2;
      let top = anchor.bottom + gap;
      if (resolvedSide === "top") top = anchor.top - tip.height - gap;
      if (resolvedSide === "left") {
        left = anchor.left - tip.width - gap;
        top = anchor.top + (anchor.height - tip.height) / 2;
      }
      if (resolvedSide === "right") {
        left = anchor.right + gap;
        top = anchor.top + (anchor.height - tip.height) / 2;
      }

      setPosition({
        left: Math.min(Math.max(left, edge), window.innerWidth - tip.width - edge),
        top: Math.min(Math.max(top, edge), window.innerHeight - tip.height - edge),
        side: resolvedSide,
      });
    }

    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
    };
  }, [show, side, label]);

  useEffect(() => {
    if (!show) return undefined;
    function closeOnEscape(event) {
      if (event.key === "Escape") leave();
    }
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [show]);

  return (
    <span
      className='tooltip-wrap'
      ref={root}
      onPointerEnter={enter}
      onPointerLeave={leave}
      onFocus={enter}
      onBlur={leave}
      aria-describedby={show ? tooltipId : undefined}
    >
      {children}
      {show &&
        createPortal(
          <span
            id={tooltipId}
            ref={popup}
            className='tooltip-popup'
            data-side={position.side}
            role='tooltip'
            style={{ left: position.left, top: position.top }}
          >
            {label}
          </span>,
          document.body,
        )}
    </span>
  );
}
