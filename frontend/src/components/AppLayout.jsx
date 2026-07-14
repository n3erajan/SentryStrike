import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar.jsx";

// Shell for the authenticated app: the fixed vertical sidebar on the left and
// the routed page content on the right. Individual pages keep their own
// .page / .page-wide width containers.
function AppLayout() {
  return (
    <div className='app-shell'>
      <Sidebar />
      <main className='app-main'>
        <Outlet />
      </main>
    </div>
  );
}

export default AppLayout;
