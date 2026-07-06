import { SEVERITY_META } from "../data/constants.js";

function SeverityBadge({ severity }) {
  const m = SEVERITY_META[severity] || SEVERITY_META.low;
  const Icon = m.Icon;
  return (
    <span
      className='badge'
      style={{ color: m.color, background: m.bg, borderColor: m.border }}
    >
      <Icon size={12} weight='fill' /> {m.label}
    </span>
  );
}

export default SeverityBadge;
