import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check, ChevronDown } from "lucide-react";

export default function Select({
  value,
  onChange,
  options = [],
  disabled = false,
  placeholder = "",
  className = "",
  ariaLabel,
}) {
  const root = useRef(null);
  const menu = useRef(null);
  const listboxId = useId();
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [position, setPosition] = useState({
    left: 0,
    top: 0,
    width: 0,
    side: "bottom",
  });
  const selected = options.find((option) => option.value === value);
  const selectedIndex = options.findIndex((option) => option.value === value);

  function openMenu() {
    if (disabled || options.length === 0) return;
    setActiveIndex(selectedIndex >= 0 ? selectedIndex : 0);
    setOpen(true);
  }

  function choose(option) {
    onChange(option.value);
    setOpen(false);
    root.current?.querySelector(".sel-trigger")?.focus();
  }

  useEffect(() => {
    if (!open) return undefined;
    function closeOutside(event) {
      if (
        !root.current?.contains(event.target) &&
        !menu.current?.contains(event.target)
      )
        setOpen(false);
    }
    document.addEventListener("pointerdown", closeOutside);
    return () => document.removeEventListener("pointerdown", closeOutside);
  }, [open]);

  useLayoutEffect(() => {
    if (!open) return undefined;

    function updatePosition() {
      if (!root.current || !menu.current) return;
      const anchor = root.current.getBoundingClientRect();
      const menuRect = menu.current.getBoundingClientRect();
      const edge = 8;
      const gap = 6;
      const roomBelow = window.innerHeight - anchor.bottom - edge;
      const roomAbove = anchor.top - edge;
      const side =
        menuRect.height > roomBelow && roomAbove > roomBelow ? "top" : "bottom";
      const width = Math.min(
        Math.max(anchor.width, 180),
        window.innerWidth - edge * 2,
      );
      const left = Math.min(
        Math.max(anchor.left, edge),
        window.innerWidth - width - edge,
      );
      const top =
        side === "top"
          ? Math.max(edge, anchor.top - menuRect.height - gap)
          : Math.min(
              anchor.bottom + gap,
              window.innerHeight - menuRect.height - edge,
            );
      setPosition({ left, top, width, side });
    }

    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
    };
  }, [open]);

  function handleKeyDown(event) {
    if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      if (!open) {
        openMenu();
        return;
      }
      if (event.key === "Home") setActiveIndex(0);
      else if (event.key === "End") setActiveIndex(options.length - 1);
      else
        setActiveIndex((index) =>
          event.key === "ArrowDown"
            ? (index + 1) % options.length
            : (index - 1 + options.length) % options.length,
        );
    } else if (event.key === "Enter" && open) {
      event.preventDefault();
      if (options[activeIndex]) choose(options[activeIndex]);
    } else if (event.key === "Escape" && open) {
      event.preventDefault();
      setOpen(false);
    }
  }

  return (
    <div
      className={`sel${open ? " open" : ""}${disabled ? " disabled" : ""}${className ? ` ${className}` : ""}`}
      ref={root}
    >
      <button
        type='button'
        className='sel-trigger'
        aria-label={ariaLabel}
        onClick={() => (open ? setOpen(false) : openMenu())}
        onKeyDown={handleKeyDown}
        disabled={disabled}
        aria-haspopup='listbox'
        aria-expanded={open}
        aria-controls={open ? listboxId : undefined}
        aria-activedescendant={
          open && options[activeIndex]
            ? `${listboxId}-option-${activeIndex}`
            : undefined
        }
      >
        <span className={selected ? "" : "sel-placeholder"}>
          {selected ? selected.label : placeholder}
        </span>
        <ChevronDown className='ico sel-arrow' />
      </button>
      {open &&
        createPortal(
          <div
            id={listboxId}
            ref={menu}
            className='sel-menu'
            data-side={position.side}
            role='listbox'
            style={{
              left: position.left,
              top: position.top,
              width: position.width,
            }}
          >
            {options.map((option, index) => (
              <button
                id={`${listboxId}-option-${index}`}
                key={option.value}
                type='button'
                className={`sel-opt${option.value === value ? " active" : ""}${index === activeIndex ? " focused" : ""}`}
                role='option'
                aria-selected={option.value === value}
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => choose(option)}
              >
                <span>{option.label}</span>
                {option.value === value && <Check className='sel-check' />}
              </button>
            ))}
          </div>,
          document.body,
        )}
    </div>
  );
}
