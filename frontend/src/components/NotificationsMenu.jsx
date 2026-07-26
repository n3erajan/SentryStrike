import { useCallback, useEffect, useRef, useState } from "react";
import { Bell, CheckCheck, Loader2, X } from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
  getUnreadCount,
  listNotifications,
  markAllNotificationsRead,
  markNotificationRead,
} from "../services/notifications.js";
import Tooltip from "./Tooltip.jsx";

const PAGE_SIZE = 15;

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
  }, [open, loadingMore, exhausted]);

  async function loadMore() {
    setLoadingMore(true);
    try {
      const batch = await listNotifications({ skip: items.length, limit: PAGE_SIZE });
      const newItems = batch.items || [];
      setItems((prev) => [...prev, ...newItems]);
      if (newItems.length < PAGE_SIZE) setExhausted(true);
    } finally {
      setLoadingMore(false);
    }
  }

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
                {items.map((item) => (
                  <button
                    key={item.id}
                    className={`notification-item${item.read_at ? "" : " unread"}`}
                    onClick={() => select(item)}
                  >
                    <b>{item.title}</b>
                    <span>{item.message}</span>
                    <small>
                      {new Date(item.created_at).toLocaleString(undefined, {
                        dateStyle: "medium",
                        timeStyle: "short",
                      })}
                    </small>
                  </button>
                ))}
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
              <div className='empty-state'>You’re all caught up.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
