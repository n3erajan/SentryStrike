import { Routes, Route, Navigate } from "react-router-dom";
import "./App.css";
import AppLayout from "./components/AppLayout.jsx";
import ProtectedRoute from "./components/ProtectedRoute.jsx";
import { PublicOnlyRoute } from "./components/ProtectedRoute.jsx";
import LandingPage from "./pages/LandingPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import RegisterPage from "./pages/RegisterPage.jsx";
import ScanPage from "./pages/ScanPage.jsx";
import ActiveScansPage from "./pages/ActiveScansPage.jsx";
import ActiveScanPage from "./pages/ActiveScanPage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import ReportPage from "./pages/ReportPage.jsx";

// Route map (see plan). Public marketing + auth screens live at the root; the
// authenticated app is nested under /app behind the vertical-sidebar layout.
function App() {
  return (
    <Routes>
      {/* Public — redirect to the app when already signed in. */}
      <Route element={<PublicOnlyRoute />}>
        <Route path='/' element={<LandingPage />} />
        <Route path='/login' element={<LoginPage />} />
        <Route path='/register' element={<RegisterPage />} />
      </Route>

      {/* Protected app shell with the left sidebar. */}
      <Route element={<ProtectedRoute />}>
        <Route path='/app' element={<AppLayout />}>
          <Route index element={<Navigate to='scan' replace />} />
          <Route path='scan' element={<ScanPage />} />
          <Route path='active' element={<ActiveScansPage />} />
          <Route path='active/:scanId' element={<ActiveScanPage />} />
          <Route path='history' element={<HistoryPage />} />
          <Route path='report/:scanId' element={<ReportPage />} />
        </Route>
      </Route>

      <Route path='*' element={<Navigate to='/' replace />} />
    </Routes>
  );
}

export default App;
