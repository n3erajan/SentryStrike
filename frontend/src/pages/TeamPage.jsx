import { useCallback, useEffect, useState } from "react";
import { Loader2, MailPlus, Trash2, X } from "lucide-react";
import { useAuth } from "../context/AuthContext.jsx";
import { useToast } from "../components/Toast.jsx";
import { cancelInvite, changeMemberRole, inviteMember, listInvites, listMembers, removeMember } from "../services/workspace.js";

const ROLES = ["admin", "analyst", "developer", "viewer"];
const title = (v) => (v || "").replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
const date = (v) => v ? new Date(v).toLocaleDateString() : "—";

function TeamPage() {
  const { user } = useAuth();
  const toast = useToast();
  const admin = ["owner", "admin"].includes(user?.role);
  const [members, setMembers] = useState([]);
  const [invites, setInvites] = useState([]);
  const [seatInfo, setSeatInfo] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showInvite, setShowInvite] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("developer");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const memberData = await listMembers();
      setMembers(memberData.items || []); setSeatInfo(memberData);
      if (admin) setInvites((await listInvites()).items || []);
    } catch (err) { setError(err.message || "Could not load the workspace."); }
    finally { setLoading(false); }
  }, [admin]);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load();
  }, [load]);

  async function submitInvite(e) {
    e.preventDefault(); setBusy("invite");
    try { await inviteMember(email, role); setEmail(""); setShowInvite(false); toast("Invitation sent"); await load(); }
    catch (err) { toast(err.message || "Could not send invitation."); }
    finally { setBusy(""); }
  }
  async function updateRole(member, nextRole) {
    setBusy(member.id);
    try { await changeMemberRole(member.id, nextRole); toast("Role updated"); await load(); }
    catch (err) { toast(err.message || "Could not update role."); }
    finally { setBusy(""); }
  }
  async function remove(member) {
    if (!window.confirm(`Remove ${member.email} from this workspace? Their account and sessions will be deleted.`)) return;
    setBusy(member.id);
    try { await removeMember(member.id); toast("Member removed"); await load(); }
    catch (err) { toast(err.message || "Could not remove member."); }
    finally { setBusy(""); }
  }
  async function cancel(invite) {
    setBusy(invite.id);
    try { await cancelInvite(invite.id); toast("Invitation cancelled"); await load(); }
    catch (err) { toast(err.message || "Could not cancel invitation."); }
    finally { setBusy(""); }
  }

  return <div className='view'>
    <div className='head'><div><h1>Team</h1><p>{seatInfo.occupied_seats ?? members.length} of {seatInfo.member_limit ?? "—"} workspace seats occupied.</p></div>
      {admin && <button className='btn primary' onClick={() => setShowInvite(true)} disabled={seatInfo.occupied_seats >= seatInfo.member_limit}><MailPlus className='ico' />Invite member</button>}
    </div>
    {error && <div className='auth-error'>{error}</div>}
    {loading ? <div className='empty-state'><Loader2 className='ico spin' /> Loading team…</div> : <div className='team-table'>
      <div className='team-head'><span>Member</span><span>Role</span><span>Joined</span><span>Status</span><span></span></div>
      {members.map((m) => { const immutable = !admin || m.role === "owner" || m.id === user?.id; return <div key={m.id} className='team-row'>
        <div><b>{m.full_name}{m.id === user?.id ? " (you)" : ""}</b><div className='small'>{m.email}</div></div>
        <span>{immutable ? title(m.role) : <select value={m.role} disabled={busy === m.id} onChange={(e) => updateRole(m, e.target.value)}>{ROLES.map((r) => <option key={r} value={r}>{title(r)}</option>)}</select>}</span>
        <span>{date(m.created_at)}</span><span className={m.is_active ? "low" : "muted-text"}>● {m.is_active ? "Active" : "Inactive"}</span>
        <span>{!immutable && <button className='icon-btn danger' onClick={() => remove(m)} aria-label={`Remove ${m.email}`}><Trash2 className='ico' /></button>}</span>
      </div>; })}
    </div>}

    {admin && invites.length > 0 && <div className='panel'><div className='panel-h'>Pending invitations</div><div className='panel-b compact-list'>{invites.map((i) => <div className='invite-row' key={i.id}><div><b>{i.email}</b><div className='small'>{title(i.role)} · expires {date(i.expires_at)}</div></div><span className='status-pill'>{title(i.email_delivery_status)}</span><button className='icon-btn' onClick={() => cancel(i)} disabled={busy === i.id} aria-label='Cancel invitation'><X className='ico' /></button></div>)}</div></div>}

    {showInvite && <div className='modal-backdrop' onMouseDown={() => setShowInvite(false)}><div className='modal-card' onMouseDown={(e) => e.stopPropagation()}><button className='modal-close' onClick={() => setShowInvite(false)}><X className='ico' /></button><h2>Invite a teammate</h2><p className='muted-text'>The email address and role are locked into the invitation.</p><form onSubmit={submitInvite}><div className='field'><label>Work email</label><div className='control'><input type='email' required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus /></div></div><div className='field'><label>Role</label><div className='control'><select value={role} onChange={(e) => setRole(e.target.value)}>{ROLES.map((r) => <option key={r} value={r}>{title(r)}</option>)}</select></div></div><button className='btn primary' disabled={busy === "invite"}>{busy === "invite" ? "Sending…" : "Send invitation"}</button></form></div></div>}
  </div>;
}

export default TeamPage;
