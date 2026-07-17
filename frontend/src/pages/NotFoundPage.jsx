import { Link } from "react-router-dom";
import { ShieldCheck, ArrowLeft } from "lucide-react";

function NotFoundPage() {
  return (
    <main
      style={{
        display: "grid",
        placeItems: "center",
        minHeight: "100dvh",
        padding: 20,
        background: "var(--bg)",
        color: "var(--ink)",
        fontFamily: '"DM Sans", system-ui, sans-serif',
      }}
    >
      <div className='card' style={{ maxWidth: 520 }}>
        <span className='mark'>
          <ShieldCheck className='ico' />
        </span>
        <span
          className='mono'
          style={{
            display: "block",
            marginTop: 20,
            fontSize: "0.7rem",
            color: "var(--brand)",
            fontWeight: 700,
          }}
        >
          404 / ROUTE NOT FOUND
        </span>
        <h1
          style={{ marginTop: 8, fontSize: "1.8rem", letterSpacing: "-0.03em" }}
        >
          This page is outside the scan scope.
        </h1>
        <p style={{ marginTop: 10, color: "var(--sub)", fontSize: "0.8rem" }}>
          The address may be incorrect or the page may have moved.
        </p>
        <Link to='/' className='btn primary' style={{ marginTop: 20 }}>
          <ArrowLeft className='ico' />
          Return home
        </Link>
      </div>
    </main>
  );
}

export default NotFoundPage;
