import { useEffect, useMemo, useRef, useState } from "react";
import { MailPlus, Search, Trash2, Users, X } from "lucide-react";
import { useAuth } from "../context/AuthContext.jsx";
import { useToast } from "../components/Toast.jsx";
import Tooltip from "../components/Tooltip.jsx";
import Select from "../components/Select.jsx";
import { cancelInvite, changeMemberRole, inviteMember, listInvites, listMembers, removeMember } from "../services/workspace.js";
import ErrorNotice from "../components/ErrorNotice.jsx";
import { parseUTCDate } from "../utils/helpers.js";
import useQuery from "../hooks/useQuery.js";
import { invalidateQueries } from "../services/queryCache.js";
import QuerySwap, { QuerySkeleton, QueryContent } from "../components/QuerySwap.jsx";

const ROLES = ["admin", "analyst", "developer", "viewer"];
const EMPTY_ITEMS = [];
const title = (v) => (v || "").replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
const date = (v) => {
  const d = parseUTCDate(v);
  return d ? d.toLocaleDateString() : "N/A";
};
const inviteStatus = (s) => ({ not_attempted: "Pending", smtp_accepted: "Invited", failed: "Failed" })[s] || title(s);

function TeamPage() {
  const { user } = useAuth();
  const toast = useToast();
  const admin = ["owner", "admin"].includes(user?.role);
  const [query, setQuery] = useState("");
  const [showInvite, setShowInvite] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("developer");
  const [busy, setBusy] = useState("");
  const [memberToRemove, setMemberToRemove] = useState(null);
  const removeCancelRef = useRef(null);

  const membersQuery = useQuery({
    queryKey: "team:members",
    queryFn: listMembers,
  });
  const invitesQuery = useQuery({
    queryKey: "team:invites",
    queryFn: listInvites,
    enabled: admin,
  });
  const members = membersQuery.data?.items || EMPTY_ITEMS;
  const invites = invitesQuery.data?.items || EMPTY_ITEMS;
  const seatInfo = membersQuery.data || {};
  const loading = membersQuery.isLoading || (admin && invitesQuery.isLoading);
  const error = membersQuery.error || (admin && invitesQuery.error);
  const contentEntered =
    membersQuery.contentEntered || invitesQuery.contentEntered;
  const removeBusy = memberToRemove?.id === busy;

  useEffect(() => {
    if (!memberToRemove) return undefined;

    removeCancelRef.current?.focus();
    function closeOnEscape(event) {
      if (event.key === "Escape" && !removeBusy) setMemberToRemove(null);
    }
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [memberToRemove, removeBusy]);

  function refetch() {
    const requests = [membersQuery.refetch()];
    if (admin) requests.push(invitesQuery.refetch());
    return Promise.allSettled(requests);
  }

  async function refreshTeam() {
    invalidateQueries("audit", { refetchActive: false });
    await invalidateQueries("team");
  }

  const rows = useMemo(() => {
    const q = query.toLowerCase();
    return members.filter((m) => (m.full_name + " " + m.email).toLowerCase().includes(q));
  }, [members, query]);

  async function submitInvite(e) {
    e.preventDefault(); setBusy("invite");
    try { await inviteMember(email, role); setEmail(""); setShowInvite(false); toast("Invitation sent"); await refreshTeam(); }
    catch (err) { toast(err, { type: "error", fallback: "Could not send invitation." }); }
    finally { setBusy(""); }
  }
  async function updateRole(member, nextRole) {
    setBusy(member.id);
    try { await changeMemberRole(member.id, nextRole); toast("Role updated"); await refreshTeam(); }
    catch (err) { toast(err, { type: "error", fallback: "Could not update role." }); }
    finally { setBusy(""); }
  }
  async function remove() {
    if (!memberToRemove) return;
    const member = memberToRemove;
    setBusy(member.id);
    try { await removeMember(member.id); setMemberToRemove(null); toast("Member removed"); await refreshTeam(); }
    catch (err) { toast(err, { type: "error", fallback: "Could not remove member." }); }
    finally { setBusy(""); }
  }
  async function cancel(invite) {
    setBusy(invite.id);
    try { await cancelInvite(invite.id); toast("Invitation cancelled"); await refreshTeam(); }
    catch (err) { toast(err, { type: "error", fallback: "Could not cancel invitation." }); }
    finally { setBusy(""); }
  }

  const seatLabel = loading
    ? "Loading workspace seats…"
    : `${seatInfo.occupied_seats ?? members.length} of ${seatInfo.member_limit ?? "N/A"} seats used`;

  return <div className='view'>
    <div className='head'><div><h1>Team</h1><p>{seatLabel}</p></div>
      {admin && <button className='btn primary' onClick={() => setShowInvite(true)} disabled={seatInfo.occupied_seats >= seatInfo.member_limit}><MailPlus className='ico' />Invite member</button>}
    </div>
    <ErrorNotice error={error} fallback='Could not load the workspace.' onRetry={refetch} />
    <QuerySwap>
    {loading ? <QuerySkeleton className='team-table query-skeleton' aria-label='Loading team members'><span className='skeleton-block skeleton-search' /><div className='team-head' aria-hidden='true'><span>Member</span><span>Role</span><span>Joined</span><span>Status</span><span></span></div>{[0, 1, 2].map((item) => <div className='team-row skeleton-table-row' key={item} aria-hidden='true'><span className='skeleton-target'><span className='skeleton-block skeleton-heading' /><span className='skeleton-block skeleton-copy' /></span><span className='skeleton-block skeleton-copy' /><span className='skeleton-block skeleton-copy' /><span className='skeleton-block skeleton-copy' /><span /></div>)}</QuerySkeleton> : rows.length === 0 && !query && members.length === 0 ? (
      <div className='empty-state' key='empty'><Users size={30} /><h2>No team members</h2><p>Invite people who need access to this workspace.</p>{admin && <button className='btn primary' onClick={() => setShowInvite(true)}><MailPlus className='ico' />Invite member</button>}</div>
    ) : <QueryContent settled={contentEntered} className='team-table'>
      <label className='search'><Search className='ico' /><input placeholder='Search members' value={query} onChange={(e) => setQuery(e.target.value)} /></label>
      <div className='team-head'><span>Member</span><span>Role</span><span>Joined</span><span>Status</span><span></span></div>
      {rows.length === 0 ? <div className='empty-state'>No members match your search.</div> : rows.map((m) => { const immutable = !admin || m.role === "owner" || m.id === user?.id; return <article key={m.id} className='team-row'>
        <div><b>{m.full_name}{m.id === user?.id ? " (you)" : ""}</b><div className='small'>{m.email}</div></div>
        <span>{immutable ? title(m.role) : <Select value={m.role} onChange={(v) => updateRole(m, v)} disabled={busy === m.id} options={ROLES.map((r) => ({value: r, label: title(r)}))} />}</span>
        <span>{date(m.created_at)}</span><span className={m.is_active ? "low" : "muted-text"}>● {m.is_active ? "Active" : "Inactive"}</span>
        <span className='rowactions'>{!immutable && <Tooltip label={`Remove ${m.email}`}><button className='icon-btn danger' type='button' onClick={() => setMemberToRemove(m)} aria-label={`Remove ${m.email}`}><Trash2 className='ico' /></button></Tooltip>}</span>
      </article>; })}
    </QueryContent>}
    </QuerySwap>

    {admin && invites.length > 0 && <div className='panel' style={{ marginTop: 20 }}><div className='panel-h'>Pending invitations</div><div className='panel-b compact-list'>{invites.map((i) => <div className='invite-row' key={i.id}><div><b>{i.email}</b><div className='small'>{title(i.role)} · expires {date(i.expires_at)}</div></div><span className='status-pill'>{inviteStatus(i.email_delivery_status)}</span><Tooltip label='Cancel invitation'><button className='icon-btn' onClick={() => cancel(i)} disabled={busy === i.id} aria-label='Cancel invitation'><X className='ico' /></button></Tooltip></div>)}</div></div>}

    {memberToRemove && <div className='modal-backdrop' onMouseDown={() => { if (!removeBusy) setMemberToRemove(null); }}><div className='modal-card confirm-modal' role='alertdialog' aria-modal='true' aria-labelledby='remove-member-title' aria-describedby='remove-member-description' onMouseDown={(e) => e.stopPropagation()}><button className='modal-close' type='button' onClick={() => setMemberToRemove(null)} disabled={removeBusy} aria-label='Close'><X className='ico' /></button><h2 id='remove-member-title'>Remove team member?</h2><p className='muted-text' id='remove-member-description'><b>{memberToRemove.email}</b> will lose access to this workspace. Their account and active sessions will be deleted.</p><div className='modal-actions'><button ref={removeCancelRef} className='btn' type='button' onClick={() => setMemberToRemove(null)} disabled={removeBusy}>Cancel</button><button className='btn danger-primary' type='button' onClick={remove} disabled={removeBusy}>{removeBusy ? "Removing…" : "Remove member"}</button></div></div></div>}

    {showInvite && <div className='modal-backdrop' onMouseDown={() => setShowInvite(false)}><div className='modal-card' onMouseDown={(e) => e.stopPropagation()}><button className='modal-close' onClick={() => setShowInvite(false)} aria-label='Close'><X className='ico' /></button><h2>Invite a teammate</h2><p className='muted-text'>Choose their email and workspace role.</p><form onSubmit={submitInvite}><div className='field'><label>Work email</label><div className='control'><input type='email' required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus /></div></div><div className='field'><label>Role</label><div className='control'><Select value={role} onChange={setRole} options={ROLES.map((r) => ({value: r, label: title(r)}))} /></div></div><button className='btn primary' disabled={busy === "invite"}>{busy === "invite" ? "Sending…" : "Send invitation"}</button></form></div></div>}
  </div>;
}

export default TeamPage;
