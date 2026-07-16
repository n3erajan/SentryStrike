import { SEVERITY_META } from "../data/constants.js";

const STYLES = {
  critical: "border-[#efbbb7] bg-[#fff0ef] text-[#de3d34]",
  high: "border-[#f4c7a1] bg-[#fff5eb] text-[#b54708]",
  medium: "border-[#ead49a] bg-[#fff8e6] text-[#8a6108]",
  low: "border-[#a9ddc6] bg-[#edf9f3] text-[#1c8742]",
  info: "border-[#b9c9f5] bg-[#eef3ff] text-[#004bb7]",
  safe: "border-[#a9ddc6] bg-[#edf9f3] text-[#1c8742]",
};

function SeverityBadge({ severity }) {
  const key = (severity || "low").toString().toLowerCase();
  const meta = SEVERITY_META[key] || SEVERITY_META.low;
  const Icon = meta.Icon;
  return <span className={`inline-flex w-fit items-center gap-1 rounded border px-1.5 py-0.5 text-[8px] font-bold uppercase ${STYLES[key] || STYLES.low}`}><Icon size={10} weight='fill' />{meta.label}</span>;
}

export default SeverityBadge;
