import { useAuth } from "../context/AuthContext.jsx";
import { displayName } from "../components/Sidebar.jsx";
import { useToast } from "../components/Toast.jsx";

function TeamPage() {
  const { user } = useAuth();
  const toast = useToast();

  const members = [
    {
      name: displayName(user),
      email: user?.email || "you@example.com",
      role: "Owner",
      scope: "All apps",
      status: "Active",
    },
  ];

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>Team</h1>
          <p>Manage owners, developers, and report viewers.</p>
        </div>
        <button
          className='btn primary'
          onClick={() => toast("Invite flow is not yet available")}
        >
          Invite member
        </button>
      </div>

      <div className='team-table'>
        <div className='team-head'>
          <span>Member</span>
          <span>Role</span>
          <span>Scope</span>
          <span>Status</span>
          <span></span>
        </div>
        {members.map((m) => (
          <div key={m.email} className='team-row'>
            <div>
              <b>{m.name}</b>
              <div className='small'>{m.email}</div>
            </div>
            <span>{m.role}</span>
            <span>{m.scope}</span>
            <span className='low'>● {m.status}</span>
            <span />
          </div>
        ))}
      </div>

      <p className='help-text'>
        Additional roles (developers, report viewers) will appear here once
        invitations are enabled.
      </p>
    </div>
  );
}

export default TeamPage;
