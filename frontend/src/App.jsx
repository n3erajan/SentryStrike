import { Routes, Route, Navigate } from "react-router-dom";
import "./App.css";
import AppLayout from "./components/AppLayout.jsx";
import ProtectedRoute from "./components/ProtectedRoute.jsx";
import { PublicOnlyRoute } from "./components/ProtectedRoute.jsx";
import LandingPage from "./pages/LandingPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import RegisterPage from "./pages/RegisterPage.jsx";
import HomePage from "./pages/HomePage.jsx";
import AppsPage from "./pages/AppsPage.jsx";
import ScanPage from "./pages/ScanPage.jsx";
import ActiveScansPage from "./pages/ActiveScansPage.jsx";
import ActiveScanPage from "./pages/ActiveScanPage.jsx";
import ReportsPage from "./pages/ReportsPage.jsx";
import ReportPage from "./pages/ReportPage.jsx";
import TeamPage from "./pages/TeamPage.jsx";
import SettingsPage from "./pages/SettingsPage.jsx";
import NotFoundPage from "./pages/NotFoundPage.jsx";

function App() {
  return (
    <Routes>
      <Route element={<PublicOnlyRoute />}>
        <Route path='/' element={<LandingPage />} />
        <Route path='/login' element={<LoginPage />} />
        <Route path='/register' element={<RegisterPage />} />
      </Route>

      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route path='/home' element={<HomePage />} />
          {/* <Route path='/apps' element={<AppsPage />} /> */}
          <Route path='/scan' element={<ScanPage />} />
          <Route path='/active' element={<ActiveScansPage />} />
          <Route path='/active/:scanId' element={<ActiveScanPage />} />
          <Route path='/reports' element={<ReportsPage />} />
          <Route path='/report/:scanId' element={<ReportPage />} />
          {/* <Route path='/team' element={<TeamPage />} /> */}
          {/* <Route path='/settings' element={<SettingsPage />} /> */}
          <Route path='/history' element={<Navigate to='/reports' replace />} />
        </Route>
      </Route>

      <Route path='*' element={<NotFoundPage />} />
    </Routes>
  );
}

export default App;
