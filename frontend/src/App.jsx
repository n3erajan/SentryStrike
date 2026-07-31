import { Routes, Route, Navigate } from "react-router-dom";
import "./App.css";
import AppLayout from "./components/AppLayout.jsx";
import ProtectedRoute from "./components/ProtectedRoute.jsx";
import { PublicOnlyRoute } from "./components/ProtectedRoute.jsx";
import LandingPage from "./pages/LandingPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import RegisterPage from "./pages/RegisterPage.jsx";
import RequestAccessPage from "./pages/RequestAccessPage.jsx";
import HomePage from "./pages/HomePage.jsx";
import AppsPage from "./pages/AppsPage.jsx";
import ApplicationPage from "./pages/ApplicationPage.jsx";
import ScanPage from "./pages/ScanPage.jsx";
import ScansPage from "./pages/ScansPage.jsx";
import ScanDetailPage from "./pages/ScanDetailPage.jsx";
import ReportsPage from "./pages/ReportsPage.jsx";
import ReportPage from "./pages/ReportPage.jsx";
import TeamPage from "./pages/TeamPage.jsx";
import SettingsPage from "./pages/SettingsPage.jsx";
import PrivacyPage from "./pages/PrivacyPage.jsx";
import TermsPage from "./pages/TermsPage.jsx";
import NotFoundPage from "./pages/NotFoundPage.jsx";

function App() {
  return (
    <Routes>
      <Route element={<PublicOnlyRoute />}>
        <Route path='/' element={<LandingPage />} />
        <Route path='/login' element={<LoginPage />} />
        <Route path='/register' element={<RegisterPage />} />
        <Route path='/request-access' element={<RequestAccessPage />} />
      </Route>

      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route path='/home' element={<HomePage />} />
          <Route path='/apps' element={<AppsPage />} />
          <Route path='/apps/:appId' element={<ApplicationPage />} />
          <Route path='/scan' element={<ScanPage />} />
          <Route path='/scans' element={<ScansPage />} />
          <Route path='/scans/:scanId' element={<ScanDetailPage />} />
          <Route path='/reports' element={<ReportsPage />} />
          <Route path='/report/:scanId' element={<ReportPage />} />
          <Route path='/team' element={<TeamPage />} />
          <Route path='/settings' element={<SettingsPage />} />
          <Route path='/history' element={<Navigate to='/reports' replace />} />
        </Route>
      </Route>

      {/* Readable signed in or out, so these sit outside both route guards. */}
      <Route path='/privacy' element={<PrivacyPage />} />
      <Route path='/terms' element={<TermsPage />} />

      <Route path='*' element={<NotFoundPage />} />
    </Routes>
  );
}

export default App;
