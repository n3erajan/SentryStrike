import { useState, useEffect } from "react";

function ringColor(score, higherIsWorse) {
  const good = "#22c55e";
  const warn = "#eab308";
  const bad = "#f97316";
  const crit = "#ef4444";
  if (higherIsWorse) {
    if (score >= 75) return crit;
    if (score >= 50) return bad;
    if (score >= 25) return warn;
    return good;
  }
  if (score >= 80) return good;
  if (score >= 60) return warn;
  if (score >= 40) return bad;
  return crit;
}

// A circular gauge. `higherIsWorse` flips the color scale so a risk score
// (0 = safe, 100 = maximum risk) reads red at the top end.
function ScoreRing({ score = 0, caption = "/ 100", higherIsWorse = false }) {
  const value = Math.max(0, Math.min(100, Math.round(score)));
  const r = 46;
  const circ = 2 * Math.PI * r;
  const offset = circ - (value / 100) * circ;
  const color = ringColor(value, higherIsWorse);

  const [animated, setAnimated] = useState(false);
  useEffect(() => {
    const id = setTimeout(() => setAnimated(true), 100);
    return () => clearTimeout(id);
  }, []);

  return (
    <div className='score-ring-wrap'>
      <div style={{ position: "relative", width: 120, height: 120 }}>
        <svg
          width='120'
          height='120'
          style={{ transform: "rotate(-90deg)" }}
          viewBox='0 0 100 100'
        >
          <circle
            cx='50'
            cy='50'
            r={r}
            fill='none'
            stroke='rgba(255,255,255,0.08)'
            strokeWidth='7'
          />
          <circle
            cx='50'
            cy='50'
            r={r}
            fill='none'
            stroke={color}
            strokeWidth='7'
            strokeLinecap='round'
            strokeDasharray={circ}
            strokeDashoffset={animated ? offset : circ}
            style={{
              transition: "stroke-dashoffset 1.4s cubic-bezier(0.4,0,0.2,1)",
            }}
          />
        </svg>
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <div className='score-num' style={{ color }}>
            {value}
          </div>
          <div className='score-sub'>{caption}</div>
        </div>
      </div>
    </div>
  );
}

export default ScoreRing;
