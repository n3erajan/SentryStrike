/* Shared motion tokens for the landing page.
   Feel: subtle & confident — opacity + small translate + blur,
   springs with no bounce. */

export const SPRING = { type: "spring", duration: 0.7, bounce: 0 };
export const SPRING_FAST = { type: "spring", duration: 0.38, bounce: 0 };
/* Trigger reveals only once the element is well inside the viewport,
   so the motion is visible while scrolling instead of already done. */
export const VIEWPORT = { once: true, margin: "0px 0px -160px 0px" };

export const fadeUp = {
  hidden: { opacity: 0, y: 34, filter: "blur(6px)" },
  visible: {
    opacity: 1,
    y: 0,
    filter: "blur(0px)",
    transition: SPRING,
  },
};

export const staggerParent = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.12, delayChildren: 0.05 } },
};
