import React, { useState } from "react";
import "./App.css";
import Navbar from "./components/Navbar.jsx";
import ScanPage from "./pages/ScanPage.jsx";
import ReportPage from "./pages/ReportPage.jsx";

function App() {
  const [page, setPage] = useState("scan");
  const [target, setTarget] = useState("");

  function handleScanComplete(url) {
    setTarget(url);
    setPage("report");
  }

  return (
    <>
      <div className='grid-bg' />
      <Navbar
        page={page}
        onGoScan={() => setPage("scan")}
        onGoReport={() => {
          if (target) setPage("report");
        }}
        hasReport={!!target}
      />
      {page === "scan" ? (
        <ScanPage onComplete={handleScanComplete} />
      ) : (
        <ReportPage target={target} onBack={() => setPage("scan")} />
      )}
    </>
  );
}

export default App;
