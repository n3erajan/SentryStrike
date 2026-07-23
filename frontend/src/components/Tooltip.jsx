import { useRef, useState } from "react";

export default function Tooltip({ children, label, side = "bottom" }) {
  const root = useRef(null);
  const [show, setShow] = useState(false);
  const [timer, setTimer] = useState(null);

  function enter() {
    clearTimeout(timer);
    setTimer(setTimeout(() => setShow(true), 400));
  }
  function leave() {
    clearTimeout(timer);
    setShow(false);
  }

  return (
    <span className="tooltip-wrap" ref={root} onMouseEnter={enter} onMouseLeave={leave} onFocus={enter} onBlur={leave}>
      {children}
      {show && <span className={`tooltip-popup ${side}`} role="tooltip">{label}</span>}
    </span>
  );
}
