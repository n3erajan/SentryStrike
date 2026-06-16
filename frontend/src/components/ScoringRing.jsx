import React, { useState, useEffect } from "react";

function ScoreRing({ score }) {
  const r = 46,
    circ = 2 * Math.PI * r,
    offset = circ - (score / 100) * circ;
  const color =
    score >= 80
      ? "#22c55e"
      : score >= 60
        ? "#eab308"
        : score >= 40
          ? "#f97316"
          : "#ef4444";
  const [animated, setAnimated] = useState(false);
  useEffect(() => {
    setTimeout(() => setAnimated(true), 100);
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
            stroke='rgba(255,255,255,0.06)'
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
            {score}
          </div>
          <div className='score-sub'>/ 100</div>
        </div>
      </div>
    </div>
  );
}

export default ScoreRing;
