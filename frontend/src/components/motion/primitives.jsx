import { AnimatePresence, motion } from "motion/react";
import { SPRING, SPRING_FAST, VIEWPORT, fadeUp, staggerParent } from "./tokens.js";

/* Shared motion components for the landing page. Reduced motion is
   handled globally by <MotionConfig reducedMotion="user"> at the
   landing root. Tokens (springs, variants) live in tokens.js. */

/* Fades + slides a block up once it scrolls into view. */
export function Reveal({ as = "div", delay = 0, ...props }) {
  const Tag = motion[as];
  return (
    <Tag
      initial={{ opacity: 0, y: 34, filter: "blur(6px)" }}
      whileInView={{ opacity: 1, y: 0, filter: "blur(0px)" }}
      viewport={VIEWPORT}
      transition={{ ...SPRING, delay }}
      {...props}
    />
  );
}

/* Parent that reveals its StaggerItem children one-by-one on scroll. */
export function StaggerGroup({ as = "div", ...props }) {
  const Tag = motion[as];
  return (
    <Tag
      initial='hidden'
      whileInView='visible'
      viewport={VIEWPORT}
      variants={staggerParent}
      {...props}
    />
  );
}

export function StaggerItem({ as = "div", ...props }) {
  const Tag = motion[as];
  return <Tag variants={fadeUp} {...props} />;
}

/* Per-word headline reveal. Words rise into place with a slight
   stagger; the full text stays available to screen readers. */
export function AnimatedWords({ text, className, delay = 0 }) {
  const words = text.split(" ");
  return (
    <motion.h1
      className={className}
      aria-label={text}
      initial='hidden'
      animate='visible'
      variants={{
        hidden: {},
        visible: {
          transition: { staggerChildren: 0.07, delayChildren: delay },
        },
      }}
    >
      {words.map((word, i) => (
        <motion.span
          key={`${word}-${i}`}
          aria-hidden='true'
          style={{ display: "inline-block", whiteSpace: "pre" }}
          variants={{
            hidden: { opacity: 0, y: "0.4em", filter: "blur(5px)" },
            visible: {
              opacity: 1,
              y: 0,
              filter: "blur(0px)",
              transition: SPRING,
            },
          }}
        >
          {i < words.length - 1 ? `${word} ` : word}
        </motion.span>
      ))}
    </motion.h1>
  );
}

/* Cross-fades tab content when `id` changes: incoming fades up,
   outgoing exits subtler (smaller move, less blur). */
export function SwitchPane({ id, children, ...props }) {
  return (
    <AnimatePresence mode='wait' initial={false}>
      <motion.div
        key={id}
        initial={{ opacity: 0, y: 10, filter: "blur(4px)" }}
        animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
        exit={{ opacity: 0, y: -6, filter: "blur(2px)" }}
        transition={SPRING_FAST}
        {...props}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
}
