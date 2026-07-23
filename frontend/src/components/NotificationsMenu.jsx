import { useCallback, useEffect, useRef, useState } from "react";
import { Bell, CheckCheck, Loader2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { getUnreadCount, listNotifications, markAllNotificationsRead, markNotificationRead } from "../services/notifications.js";
import Tooltip from "./Tooltip.jsx";

function targetFor(item) {
  const scanId = item.metadata?.scan_id || (item.resource_type === "scan" ? item.resource_id : null);
  if (!scanId) return null;
  return item.type?.startsWith("scan_") ? `/active/${scanId}` : `/report/${scanId}`;
}

export default function NotificationsMenu() {
  const navigate = useNavigate();
  const root = useRef(null);
  const [open, setOpen] = useState(false);
  const [count, setCount] = useState(0);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);

  const refreshCount = useCallback(() => getUnreadCount().then((d) => setCount(d.count || 0)).catch(() => {}), []);
  useEffect(() => { refreshCount(); const timer = setInterval(refreshCount, 30000); return () => clearInterval(timer); }, [refreshCount]);
  useEffect(() => {
    function outside(e) { if (!root.current?.contains(e.target)) setOpen(false); }
    document.addEventListener("mousedown", outside); return () => document.removeEventListener("mousedown", outside);
  }, []);

  async function toggle() {
    const next = !open; setOpen(next);
    if (next) { setLoading(true); try { setItems((await listNotifications()).items || []); } finally { setLoading(false); } }
  }
  async function select(item) {
    if (!item.read_at) { await markNotificationRead(item.id).catch(() => {}); setCount((v) => Math.max(0, v - 1)); }
    setOpen(false); const target = targetFor(item); if (target) navigate(target);
  }
  async function readAll() {
    await markAllNotificationsRead(); setCount(0); setItems((all) => all.map((i) => ({ ...i, read_at: i.read_at || new Date().toISOString() })));
  }

  return <div className='notifications' ref={root}>
    <Tooltip label='Notifications'>
      <button className='icon-btn notification-trigger' onClick={toggle} aria-label={`Notifications${count ? `, ${count} unread` : ""}`} aria-expanded={open}><Bell className='ico' />{count > 0 && <span>{count > 99 ? "99+" : count}</span>}</button>
    </Tooltip>
    {open && <div className='notification-menu'><div className='notification-head'><b>Notifications</b><button className='text-btn' onClick={readAll} disabled={!count}><CheckCheck className='ico' />Mark all read</button></div>
      <div className='notification-list'>{loading ? <div className='empty-state'><Loader2 className='ico spin' />Loading…</div> : items.length ? items.map((item) => <button key={item.id} className={`notification-item${item.read_at ? "" : " unread"}`} onClick={() => select(item)}><b>{item.title}</b><span>{item.message}</span><small>{new Date(item.created_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}</small></button>) : <div className='empty-state'>You’re all caught up.</div>}</div>
    </div>}
  </div>;
}
