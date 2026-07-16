import { Routes, Route } from "react-router-dom";
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
import NotFoundPage from "./pages/NotFoundPage.jsx";

// Public marketing and auth screens live at the root. Authenticated routes
// share the vertical-sidebar layout without an additional URL prefix.
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
        <Route element={<AppLayout />}>
          <Route path='/scan' element={<ScanPage />} />
          <Route path='/active' element={<ActiveScansPage />} />
          <Route path='/active/:scanId' element={<ActiveScanPage />} />
          <Route path='/history' element={<HistoryPage />} />
          <Route path='/report/:scanId' element={<ReportPage />} />
        </Route>
      </Route>

      <Route path='*' element={<NotFoundPage />} />
    </Routes>
  );
}

export default App;
