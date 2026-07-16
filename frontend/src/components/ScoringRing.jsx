import { useEffect, useState } from "react";

function ringColor(score, higherIsWorse) {
  if (higherIsWorse) return score >= 75 ? "#de3d34" : score >= 50 ? "#b54708" : score >= 25 ? "#8a6108" : "#1c8742";
  return score >= 80 ? "#1c8742" : score >= 60 ? "#8a6108" : score >= 40 ? "#b54708" : "#de3d34";
}

function ScoreRing({ score = 0, caption = "/ 100", higherIsWorse = false }) {
  const value = Math.max(0, Math.min(100, Math.round(score)));
  const r = 46; const circ = 2 * Math.PI * r; const offset = circ - (value / 100) * circ;
  const color = ringColor(value, higherIsWorse);
  const [animated, setAnimated] = useState(false);
  useEffect(() => { const id = setTimeout(() => setAnimated(true), 100); return () => clearTimeout(id); }, []);
  return <div className='relative size-28 shrink-0'>
    <svg className='size-28 -rotate-90' viewBox='0 0 100 100' aria-hidden='true'><circle cx='50' cy='50' r={r} fill='none' stroke='#cbd5e3' strokeWidth='6' /><circle cx='50' cy='50' r={r} fill='none' stroke={color} strokeWidth='6' strokeLinecap='round' strokeDasharray={circ} strokeDashoffset={animated ? offset : circ} className='transition-[stroke-dashoffset] duration-1000' /></svg>
    <div className='absolute inset-0 flex flex-col items-center justify-center'><span className='font-mono text-2xl font-semibold tabular-nums' style={{ color }}>{value}</span><span className='text-[8px] text-[#6f7c8c]'>{caption}</span></div>
  </div>;
}

export default ScoreRing;
