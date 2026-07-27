import { useEffect, useState } from "react";
import { useReducedMotion } from "motion/react";

const TURNSTILE_RENDER_DELAY_MS = 500;

export default function useDelayedTurnstileConfig(loadConfig) {
  const reducedMotion = useReducedMotion();
  const [siteKey, setSiteKey] = useState("");
  const [configError, setConfigError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(
      () => {
        loadConfig(controller.signal)
          .then((config) => setSiteKey(config.turnstile_site_key))
          .catch((error) => {
            if (error.name !== "AbortError") setConfigError(error);
          });
      },
      reducedMotion ? 0 : TURNSTILE_RENDER_DELAY_MS,
    );

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [loadConfig, reducedMotion]);

  return { siteKey, configError };
}
