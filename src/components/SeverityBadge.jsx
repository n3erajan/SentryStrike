import { SEVERITY_META } from "../data/constants.js";

function SeverityBadge({ severity }) {
  const m = SEVERITY_META[severity] || SEVERITY_META.low;
  return (
    <span
      className='badge'
      style={{ color: m.color, background: m.bg, borderColor: m.border }}
    >
      {m.icon} {m.label}
    </span>
  );
}

export default SeverityBadge;
