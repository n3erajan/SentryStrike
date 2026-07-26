import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ban,
  Bell,
  CheckCheck,
  CheckCircle2,
  ClipboardCheck,
  Loader2,
  MessageSquare,
  ShieldCheck,
  UserCheck,
  Users,
  X,
  XCircle,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
  getUnreadCount,
  listNotifications,
  markAllNotificationsRead,
  markNotificationRead,
} from "../services/notifications.js";
import Tooltip from "./Tooltip.jsx";

const PAGE_SIZE = 15;

/* Icon + accent per backend NotificationType; unknown types fall back
   to a neutral bell. */
const TYPE_META = {
  scan_completed: { Icon: CheckCircle2, tone: "good" },
  scan_failed: { Icon: XCircle, tone: "bad" },
  analysis_failed: { Icon: XCircle, tone: "bad" },
  scan_cancelled: { Icon: Ban, tone: "muted" },
  finding_assigned: { Icon: UserCheck, tone: "brand" },
  finding_commented: { Icon: MessageSquare, tone: "brand" },
  finding_review_changed: { Icon: ClipboardCheck, tone: "warn" },
  remediation_status_changed: { Icon: ClipboardCheck, tone: "warn" },
  reverification_completed: { Icon: ShieldCheck, tone: "good" },
  analysis_completed: { Icon: ShieldCheck, tone: "good" },
  member_role_changed: { Icon: Users, tone: "muted" },
};

function typeMeta(type) {
  return TYPE_META[type] || { Icon: Bell, tone: "muted" };
}

function timeAgo(iso) {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const s = Math.max(0, (Date.now() - then) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  if (s < 604800) return `${Math.round(s / 86400)}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });
}

function targetFor(item) {
  const scanId =
    item.metadata?.scan_id ||
    (item.resource_type === "scan" ? item.resource_id : null);
  if (!scanId) return null;
  return item.type?.startsWith("scan_")
    ? `/active/${scanId}`
    : `/report/${scanId}`;
}

export default function NotificationsMenu() {
  const navigate = useNavigate();
  const root = useRef(null);
  const sentinelRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [count, setCount] = useState(0);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [exhausted, setExhausted] = useState(false);

  const refreshCount = useCallback(
    () =>
      getUnreadCount()
        .then((d) => setCount(d.count || 0))
        .catch(() => {}),
    [],
  );
  useEffect(() => {
    refreshCount();
    const timer = setInterval(refreshCount, 30000);
    return () => clearInterval(timer);
  }, [refreshCount]);
  useEffect(() => {
    function outside(e) {
      if (!root.current?.contains(e.target)) setOpen(false);
    }
    document.addEventListener("mousedown", outside);
    return () => document.removeEventListener("mousedown", outside);
  }, []);

  const loadMore = useCallback(async () => {
    setLoadingMore(true);
    try {
      const batch = await listNotifications({ skip: items.length, limit: PAGE_SIZE });
      const newItems = batch.items || [];
      setItems((prev) => [...prev, ...newItems]);
      if (newItems.length < PAGE_SIZE) setExhausted(true);
    } finally {
      setLoadingMore(false);
    }
  }, [items.length]);

  useEffect(() => {
    if (!open) return;
    const sentinel = sentinelRef.current;
    if (!sentinel) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !loadingMore && !exhausted) {
          loadMore();
        }
      },
      { rootMargin: "100px" },
    );
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [open, loadingMore, exhausted, loadMore]);

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (next) {
      setLoading(true);
      setExhausted(false);
      try {
        const batch = await listNotifications({ skip: 0, limit: PAGE_SIZE });
        const firstPage = batch.items || [];
        setItems(firstPage);
        if (firstPage.length < PAGE_SIZE) setExhausted(true);
      } finally {
        setLoading(false);
      }
    }
  }
  async function select(item) {
    if (!item.read_at) {
      await markNotificationRead(item.id).catch(() => {});
      setCount((v) => Math.max(0, v - 1));
    }
    setOpen(false);
    const target = targetFor(item);
    if (target) navigate(target);
  }
  async function readAll() {
    await markAllNotificationsRead();
    setCount(0);
    setItems((all) =>
      all.map((i) => ({
        ...i,
        read_at: i.read_at || new Date().toISOString(),
      })),
    );
  }

  return (
    <div className='notifications' ref={root}>
      <Tooltip label='Notifications'>
        <button
          className='icon-btn notification-trigger'
          onClick={toggle}
          aria-label={`Notifications${count ? `, ${count} unread` : ""}`}
          aria-expanded={open}
        >
          <Bell className='ico' />
          {count > 0 && <span>{count > 99 ? "99+" : count}</span>}
        </button>
      </Tooltip>
      {open && (
        <div
          className='notification-menu'
          role='dialog'
          aria-label='Notifications'
        >
          <div className='notification-head'>
            <Tooltip label='Close notifications'>
              <button
                type='button'
                className='icon-btn notification-close'
                onClick={() => setOpen(false)}
                aria-label='Close notifications'
              >
                <X className='ico' />
              </button>
            </Tooltip>
            <b>Notifications</b>
            <button className='text-btn' onClick={readAll} disabled={!count}>
              <CheckCheck className='ico' />
              Mark all read
            </button>
          </div>
          <div className='notification-list'>
            {loading ? (
              <div className='empty-state'>
                <Loader2 className='ico spin' />
                Loading…
              </div>
            ) : items.length ? (
              <>
                {items.map((item) => {
                  const { Icon, tone } = typeMeta(item.type);
                  return (
                    <button
                      key={item.id}
                      className={`notification-item${item.read_at ? "" : " unread"}`}
                      onClick={() => select(item)}
                    >
                      <span className={`notif-ico tone-${tone}`}>
                        <Icon className='ico' />
                      </span>
                      <span className='notif-body'>
                        <span className='notif-top'>
                          <b>{item.title}</b>
                          <small
                            title={new Date(item.created_at).toLocaleString(
                              undefined,
                              { dateStyle: "medium", timeStyle: "short" },
                            )}
                          >
                            {timeAgo(item.created_at)}
                          </small>
                          {!item.read_at && <i className='notif-dot' />}
                        </span>
                        <span className='notif-msg'>{item.message}</span>
                      </span>
                    </button>
                  );
                })}
                <span ref={sentinelRef} />
                {loadingMore && (
                  <div className='empty-state'>
                    <Loader2 className='ico spin' />
                    Loading more…
                  </div>
                )}
                {exhausted && items.length > PAGE_SIZE && (
                  <div className='empty-state small'>All notifications loaded</div>
                )}
              </>
            ) : (
              <div className='empty-state'>No unread notifications.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
