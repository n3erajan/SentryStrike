import { useEffect, useRef } from "react";
import { X } from "lucide-react";
import Tooltip from "./Tooltip.jsx";

export default function ReasonDialog({
  open,
  title,
  label,
  placeholder,
  defaultValue,
  confirmLabel,
  onConfirm,
  onCancel,
}) {
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const el = ref.current;
    if (!el) return;
    el.focus();
    el.setSelectionRange(el.value.length, el.value.length);
    const handler = (e) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onCancel]);

  if (!open) return null;

  function handleSubmit(e) {
    e.preventDefault();
    const val = ref.current?.value.trim();
    if (!val) return;
    onConfirm(val);
  }

  return (
    <div className='modal-backdrop' onMouseDown={onCancel}>
      <div className='modal-card' onMouseDown={(e) => e.stopPropagation()}>
        <Tooltip label='Close'>
          <button className='modal-close' onClick={onCancel} type='button'>
            <X className='ico' />
          </button>
        </Tooltip>
        <h2>{title}</h2>
        <form onSubmit={handleSubmit}>
          <div className='field'>
            <label>{label}</label>
            <div className='control'>
              <textarea
                ref={ref}
                defaultValue={defaultValue}
                placeholder={placeholder}
                rows={4}
                required
                autoFocus
              />
            </div>
          </div>
          <button className='btn primary' type='submit'>
            {confirmLabel}
          </button>
          <button className='btn' type='button' onClick={onCancel}>
            Cancel
          </button>
        </form>
      </div>
    </div>
  );
}
