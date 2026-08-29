import { ChevronLeft, ChevronRight } from "lucide-react";
import { paginate } from "../utils/helpers.js";

// Shared pager for the reports and scans lists, which previously carried
// identical copies of the markup and the page-number maths. Renders nothing for
// a single page, so callers don't need to guard the call.
function Pagination({ page, totalPages, onChange, label = "Pagination" }) {
  if (totalPages <= 1) return null;

  return (
    <nav className='pagination' aria-label={label}>
      <button
        type='button'
        className='btn page-btn'
        disabled={page <= 1}
        aria-label='Previous page'
        onClick={() => onChange(page - 1)}
      >
        <ChevronLeft className='ico' />
        Prev
      </button>
      {paginate(page, totalPages).map((p, i) =>
        p === "…" ? (
          <span key={`gap-${i}`} className='page-ellipsis' aria-hidden='true'>
            …
          </span>
        ) : (
          <button
            key={p}
            type='button'
            className={`btn page-btn${p === page ? " active" : ""}`}
            aria-label={`Page ${p}`}
            aria-current={p === page ? "page" : undefined}
            onClick={() => onChange(p)}
          >
            {p}
          </button>
        ),
      )}
      <button
        type='button'
        className='btn page-btn'
        disabled={page >= totalPages}
        aria-label='Next page'
        onClick={() => onChange(page + 1)}
      >
        Next
        <ChevronRight className='ico' />
      </button>
    </nav>
  );
}

export default Pagination;
