import { Navigate, Outlet, useLocation } from "react-router-dom";
import { MotionConfig } from "motion/react";
import { useAuth } from "../context/AuthContext.jsx";

// Gate for authenticated routes. When there's no signed-in user
// we bounce to /login, remembering where the user was headed so login can send
// them back. Renders the nested routes via <Outlet /> otherwise.
function ProtectedRoute() {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) return null;
  if (!user) {
    return <Navigate to='/login' replace state={{ from: location }} />;
  }
  return <Outlet />;
}

// Inverse gate for public screens: a signed-in user is sent straight into the
// app instead of seeing them again.
export function PublicOnlyRoute() {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (user) {
    return <Navigate to='/home' replace />;
  }
  return (
    <MotionConfig reducedMotion='user'>
      <Outlet />
    </MotionConfig>
  );
}

export default ProtectedRoute;
