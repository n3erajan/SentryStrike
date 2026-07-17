import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";

// Gate for authenticated routes. When there's no signed-in user
// we bounce to /login, remembering where the user was headed so login can send
// them back. Renders the nested routes via <Outlet /> otherwise.
function ProtectedRoute() {
  const { user } = useAuth();
  const location = useLocation();

  if (!user) {
    return <Navigate to='/login' replace state={{ from: location }} />;
  }
  return <Outlet />;
}

// Inverse gate for the landing / login / register screens: a signed-in user is
// sent straight into the app instead of seeing them again.
export function PublicOnlyRoute() {
  const { user } = useAuth();
  if (user) {
    return <Navigate to='/home' replace />;
  }
  return <Outlet />;
}

export default ProtectedRoute;
