import { useState } from "react";
import "./App.css";
import Navbar from "./components/Navbar.jsx";
import ScanPage from "./pages/ScanPage.jsx";
import ReportPage from "./pages/ReportPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import RegisterPage from "./pages/RegisterPage.jsx";
import AuthHeader from "./components/AuthHeader.jsx";
import { getCurrentUser, logout } from "./services/auth.js";

function App() {
  // DEV: skip login while developing scan/report pages.
  // Revert to `useState(getCurrentUser)` before shipping.

  // const [user, setUser] = useState({ email: "dev@sentrystrike.local" });
  const [user, setUser] = useState(getCurrentUser);

  const [authView, setAuthView] = useState("login");
  const [page, setPage] = useState("scan");
  const [target, setTarget] = useState("");
  const [scanId, setScanId] = useState(null);

  function handleScanComplete({ scanId: id, target: url }) {
    setScanId(id);
    setTarget(url);
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
    return (
      <>
        <div />
        <AuthHeader />
        {authView === "login" ? (
          <LoginPage
            onAuthed={handleAuthed}
            onGoRegister={() => setAuthView("register")}
          />
        ) : (
          <RegisterPage
            onAuthed={handleAuthed}
            onGoLogin={() => setAuthView("login")}
          />
        )}
      </>
    );
  }

  return (
    <>
      <div />
      <Navbar
        page={page}
        onGoScan={() => setPage("scan")}
        onGoReport={() => {
          if (scanId) setPage("report");
        }}
        hasReport={!!scanId}
        user={user}
        onLogout={handleLogout}
      />
      {page === "scan" ? (
        <ScanPage onComplete={handleScanComplete} />
      ) : (
        <ReportPage
          scanId={scanId}
          target={target}
          onBack={() => setPage("scan")}
        />
      )}
    </>
  );
}

export default App;
