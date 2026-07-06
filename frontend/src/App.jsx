import { useState } from "react";
import "./App.css";
import Navbar from "./components/Navbar.jsx";
import ScanPage from "./pages/ScanPage.jsx";
import ReportPage from "./pages/ReportPage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import RegisterPage from "./pages/RegisterPage.jsx";
// eslint-disable-next-line no-unused-vars -- getCurrentUser is used once the dev auth bypass below is reverted
import { getCurrentUser, logout } from "./services/auth.js";

function App() {
  // DEV: skip login while developing scan/report pages.
  // Revert to `useState(getCurrentUser)` before shipping.

  const [user, setUser] = useState({ email: "dev@sentrystrike.local" });
  // const [user, setUser] = useState(getCurrentUser);

  const [authView, setAuthView] = useState("login");
  const [page, setPage] = useState("scan");
  const [target, setTarget] = useState("");
  const [scanId, setScanId] = useState(null);
  // Where the report was opened from, so its back button returns there.
  const [reportOrigin, setReportOrigin] = useState("scan");

  function handleScanComplete({ scanId: id, target: url }) {
    setScanId(id);
    setTarget(url);
    setReportOrigin("scan");
    setPage("report");
  }

  function handleOpenReport({ scanId: id, target: url }) {
    setScanId(id);
    setTarget(url);
    setReportOrigin("history");
    setPage("report");
  }

  function handleAuthed(authedUser) {
    setUser(authedUser);
    setPage("scan");
  }

  function handleLogout() {
    logout();
    setUser(null);
    setAuthView("login");
    setTarget("");
    setScanId(null);
    setPage("scan");
  }

  if (!user) {
    return authView === "login" ? (
      <LoginPage
        onAuthed={handleAuthed}
        onGoRegister={() => setAuthView("register")}
      />
    ) : (
      <RegisterPage
        onAuthed={handleAuthed}
        onGoLogin={() => setAuthView("login")}
      />
    );
  }

  return (
    <>
      <div />
      <Navbar
        page={page}
        onGoScan={() => setPage("scan")}
        onGoHistory={() => setPage("history")}
        onGoReport={() => {
          if (scanId) setPage("report");
        }}
        hasReport={!!scanId}
        user={user}
        onLogout={handleLogout}
      />
      {page === "scan" && <ScanPage onComplete={handleScanComplete} />}
      {page === "history" && (
        <HistoryPage
          onOpenReport={handleOpenReport}
          onNewScan={() => setPage("scan")}
        />
      )}
      {page === "report" && (
        <ReportPage
          scanId={scanId}
          target={target}
          onBack={() => setPage(reportOrigin)}
        />
      )}
    </>
  );
}

export default App;
