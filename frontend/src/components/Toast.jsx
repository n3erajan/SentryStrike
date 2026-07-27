import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";

const ToastContext = createContext(() => {});

export function ToastProvider({ children }) {
  const [toast, setToast] = useState(null);

  const showToast = useCallback((message, { type = "success", duration, fallback } = {}) => {
    const text = typeof message === "string" ? message : message?.message || fallback;
    if (!text) return;
    setToast({
      message: text,
      type,
      duration: duration ?? (type === "error" ? 7000 : 3500),
      id: Date.now(),
    });
  }, []);

  useEffect(() => {
    if (!toast) return undefined;
    const id = setTimeout(() => setToast(null), toast.duration);
    return () => clearTimeout(id);
  }, [toast]);

  const Icon = toast?.type === "error" ? AlertCircle : toast?.type === "info" ? Info : CheckCircle2;

  return (
    <ToastContext.Provider value={showToast}>
      {children}
      {toast && (
        <div
          className={`toast ${toast.type}`}
          role={toast.type === "error" ? "alert" : "status"}
          aria-live={toast.type === "error" ? "assertive" : "polite"}
          key={toast.id}
        >
          <Icon className='toast-icon' aria-hidden='true' />
          <span>{toast.message}</span>
          <button
            type='button'
            className='toast-dismiss'
            aria-label='Dismiss notification'
            onClick={() => setToast(null)}
          >
            <X aria-hidden='true' />
          </button>
        </div>
      )}
    </ToastContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useToast() {
  return useContext(ToastContext);
}
