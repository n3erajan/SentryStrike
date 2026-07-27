import { AlertCircle, RefreshCw } from "lucide-react";

export default function ErrorNotice({
  error,
  fallback = "We couldn't complete the request. Please try again.",
  title = "Something went wrong",
  onRetry,
  compact = false,
  className = "",
}) {
  if (!error) return null;

  const message = typeof error === "string" ? error : error.message || fallback;
  const requestId = typeof error === "object" ? error.requestId : "";

  return (
    <div
      className={`error-notice${compact ? " compact" : ""}${className ? ` ${className}` : ""}`}
      role='alert'
      aria-live='assertive'
    >
      <AlertCircle className='error-notice-icon' aria-hidden='true' />
      <div className='error-notice-copy'>
        {!compact && <strong>{title}</strong>}
        <p>{message}</p>
        {requestId && <small>Reference: {requestId}</small>}
      </div>
      {onRetry && (
        <button type='button' className='error-notice-retry' onClick={onRetry}>
          <RefreshCw className='ico' aria-hidden='true' />
          Try again
        </button>
      )}
    </div>
  );
}
