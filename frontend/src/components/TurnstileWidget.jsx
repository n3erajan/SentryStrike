import { useEffect, useRef } from "react";

const SCRIPT_ID = "cloudflare-turnstile-script";
const SCRIPT_SRC = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
let scriptPromise;

function loadTurnstile() {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (scriptPromise) return scriptPromise;

  scriptPromise = new Promise((resolve, reject) => {
    const existing = document.getElementById(SCRIPT_ID);
    const script = existing || document.createElement("script");
    const onLoad = () => {
      if (window.turnstile) {
        resolve(window.turnstile);
        return;
      }
      scriptPromise = undefined;
      script.remove();
      reject(new Error("Unable to initialize the security check."));
    };
    const onError = () => {
      scriptPromise = undefined;
      script.remove();
      reject(new Error("Unable to load the security check."));
    };

    script.addEventListener("load", onLoad, { once: true });
    script.addEventListener("error", onError, { once: true });
    if (!existing) {
      script.id = SCRIPT_ID;
      script.src = SCRIPT_SRC;
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    }
  });
  return scriptPromise;
}

export default function TurnstileWidget({
  siteKey,
  action = "request_access",
  onTokenChange,
  onError,
  resetKey,
}) {
  const containerRef = useRef(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!siteKey) return;
    if (!container) return;

    let active = true;
    let widgetId;
    onTokenChange("");

    loadTurnstile()
      .then((turnstile) => {
        if (!active || !turnstile) return;
        widgetId = turnstile.render(container, {
          sitekey: siteKey,
          theme: "auto",
          size: "flexible",
          action,
          callback: onTokenChange,
          "expired-callback": () => onTokenChange(""),
          "error-callback": () => {
            onTokenChange("");
            onError("The security check could not be completed. Please try again.");
          },
        });
      })
      .catch(() => {
        if (active) onError("The security check could not be loaded. Please try again later.");
      });

    return () => {
      active = false;
      if (widgetId != null && window.turnstile) {
        window.turnstile.remove(widgetId);
      }
    };
  }, [siteKey, action, onTokenChange, onError, resetKey]);

  if (!siteKey) {
    return <div className='turnstile-slot' role='status' aria-live='polite' />;
  }

  return <div className='turnstile-slot' ref={containerRef} />;
}
