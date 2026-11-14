import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import type { NotificationItem, User } from "../api";
import { api, setToken, timeAgo } from "../api";
import { BrandMark, Icon } from "../icons";
import CommandPalette from "./CommandPalette";

type SystemInfo = {
  runtime?: string;
  docker?: boolean;
  hostname?: string;
  version?: string;
  wings?: string;
  sentinel_port?: number;
} | null;

const NAV = {
  workspace: [
    { to: "/", label: "Overview", icon: "gauge-high", end: true },
    { to: "/billing", label: "Plans & billing", icon: "layer-group" },
    { to: "/account", label: "Account", icon: "user-gear" },
  ],
  admin: [
    { to: "/admin", label: "Administration", icon: "chart-pie", end: true },
    { to: "/admin/servers", label: "Servers", icon: "server" },
    { to: "/admin/commerce", label: "Commerce", icon: "receipt" },
    { to: "/admin/safety", label: "Safety", icon: "shield-halved" },
    { to: "/admin/nodes", label: "Nodes", icon: "network-wired" },
    { to: "/admin/locations", label: "Locations", icon: "location-dot" },
    { to: "/admin/nests", label: "Nests & eggs", icon: "layer-group" },
    { to: "/admin/users", label: "Users", icon: "users" },
    { to: "/admin/databases", label: "Database hosts", icon: "database" },
    { to: "/admin/system", label: "System health", icon: "heart-pulse" },
    { to: "/admin/activity", label: "Audit log", icon: "clock-rotate-left" },
    { to: "/admin/settings", label: "Settings", icon: "sliders" },
  ],
};

function pageLabel(pathname: string): string {
  const map: Record<string, string> = {
    "/": "Overview",
    "/billing": "Plans & billing",
    "/account": "Account",
    "/admin": "Administration",
    "/admin/commerce": "Commerce",
    "/admin/safety": "Safety",
    "/admin/servers": "Servers",
    "/admin/servers/new": "Provision server",
    "/admin/nodes": "Nodes",
    "/admin/nodes/new": "Register node",
    "/admin/locations": "Locations",
    "/admin/nests": "Nests & eggs",
    "/admin/users": "Users",
    "/admin/users/new": "Create user",
    "/admin/databases": "Database hosts",
    "/admin/system": "System health",
    "/admin/activity": "Audit log",
    "/admin/settings": "Settings",
  };
  if (map[pathname]) return map[pathname];
  if (pathname.startsWith("/server/")) return "Server console";
  if (pathname.startsWith("/admin/nodes/")) return "Node detail";
  if (pathname.startsWith("/admin/users/")) return "User detail";
  return "Workspace";
}

export default function Shell({
  user,
  system,
  onUserChange,
  refreshUser,
}: {
  user: User;
  system: SystemInfo;
  onUserChange: (user: User) => void;
  refreshUser: () => Promise<User>;
}) {
  const nav = useNavigate();
  const loc = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const [userMenu, setUserMenu] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const [notifOpen, setNotifOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [unread, setUnread] = useState(0);
  const notifRef = useRef<HTMLDivElement>(null);
  const admin = user.role === "admin";

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (!(event.metaKey || event.ctrlKey) || event.key.toLowerCase() !== "k") return;
      const target = event.target instanceof HTMLElement ? event.target : null;
      if (target?.closest("input, textarea, select, [contenteditable='true'], .xterm")) return;
      event.preventDefault();
      setPaletteOpen((open) => !open);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const shortcut = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform)
    ? "⌘K"
    : "Ctrl K";

  const loadNotifications = async () => {
    try {
      const response = await api.notifications(false, 12);
      setNotifications(response.data);
      setUnread(response.unread);
    } catch {
      /* keep the last known notification state */
    }
  };

  useEffect(() => {
    loadNotifications();
    const timer = window.setInterval(loadNotifications, 60000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    setMenuOpen(false);
    setUserMenu(false);
    setNotifOpen(false);
  }, [loc.pathname]);

  useEffect(() => {
    function close(event: MouseEvent) {
      if (!userMenuRef.current?.contains(event.target as Node)) setUserMenu(false);
      if (!notifRef.current?.contains(event.target as Node)) setNotifOpen(false);
    }
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  async function markAllRead() {
    try {
      const response = await api.readNotifications();
      setUnread(response.unread);
      setNotifications((current) => current.map((item) => ({ ...item, read: true })));
    } catch {
      /* notification read state is best effort */
    }
  }

  function logout() {
    setToken(null);
    nav("/login", { replace: true });
  }

  const runtime = system?.docker ? "Docker engine" : "Process runtime";
  const initials = (user.first_name?.[0] || user.username.slice(0, 1)).toUpperCase();
  const displayName = [user.first_name, user.last_name].filter(Boolean).join(" ") || user.username;
  const sentinelPort = system?.sentinel_port || 0;
  const sentinelUrl =
    sentinelPort && typeof window !== "undefined"
      ? `http://${window.location.hostname}:${sentinelPort}/`
      : "";

  function renderNav(items: typeof NAV.workspace) {
    return items.map((item) => (
      <NavLink key={item.to} to={item.to} end={item.end} onClick={() => setMenuOpen(false)}>
        <Icon name={item.icon} />
        <span>{item.label}</span>
      </NavLink>
    ));
  }

  return (
    <div className="shell">
      <div
        className={`sidebar-scrim ${menuOpen ? "visible" : ""}`}
        onClick={() => setMenuOpen(false)}
        aria-hidden="true"
      />
      <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
        <Link to="/" className="side-brand" aria-label="Cosmos Molorum overview">
          <BrandMark />
          <span className="word">
            Cosmos Molorum
            <small>Control plane</small>
          </span>
          <span className="brand-version">v{system?.version || "2.2.0"}</span>
        </Link>

        <nav className="nav" aria-label="Primary navigation">
          <div className="nav-label">Workspace</div>
          {renderNav(NAV.workspace)}
          {admin && (
            <>
              <div className="nav-label">Administration</div>
              {renderNav(NAV.admin)}
            </>
          )}
        </nav>

        {sentinelUrl && (
          <a
            className="side-mode"
            href={sentinelUrl}
            target="_blank"
            rel="noreferrer"
            title={`Open Cosmos Molorum Sentinel on port ${sentinelPort}`}
          >
            <span className="side-mode-icon">
              <Icon name="shield-halved" />
            </span>
            <span className="side-mode-copy">
              <small>Mode keamanan</small>
              <strong>Security testing</strong>
              <em>Sentinel · port {sentinelPort}</em>
            </span>
            <Icon name="arrow-up-right-from-square" className="side-mode-arrow" />
          </a>
        )}

        <div className="side-cta">
          <span className="side-cta-icon">
            <Icon name="circle-nodes" />
          </span>
          <div>
            <strong>{system?.hostname || "Local node"}</strong>
            <span>{runtime}</span>
          </div>
          <span className={`live-dot ${system?.docker ? "ok" : "neutral"}`} />
        </div>

        <div className="side-foot">
          <div className="side-foot-row">
            <span>Panel</span>
            <strong>{system?.version || "2.2.0"}</strong>
          </div>
          <div className="side-foot-row">
            <span>Runtime</span>
            <strong>{system?.wings || "2.2.0"}</strong>
          </div>
          <div className="side-foot-note">
            <Icon name={system?.docker ? "cube" : "microchip"} />
            {system?.docker ? "OCI workloads enabled" : "Native process isolation"}
          </div>
          <div className="side-foot-note side-shortcut">
            <Icon name="keyboard" />
            <span>Press <kbd>{shortcut}</kbd> to search</span>
          </div>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="topbar-left">
            <button
              type="button"
              className="icon-btn mobile-menu"
              onClick={() => setMenuOpen(true)}
              aria-label="Open navigation"
            >
              <Icon name="bars" />
            </button>
            <div className="crumbs">
              <Link to="/" className="crumb-root">
                <Icon name="house" /> <span className="crumb-brand-full">Cosmos Molorum</span><span className="crumb-brand-short">Cosmos</span>
              </Link>
              <span className="sep">/</span>
              <strong>{pageLabel(loc.pathname)}</strong>
            </div>
          </div>
          <div className="topbar-right">
            <button
              type="button"
              className="topbar-search"
              onClick={() => setPaletteOpen(true)}
              aria-label="Search pages and workloads, Control K"
              title="Search the panel (Ctrl K)"
            >
              <Icon name="magnifying-glass" />
              <span className="topbar-search-label">Search</span>
              <kbd>{shortcut}</kbd>
            </button>
            <span className="runtime-pill" title={`${runtime} on ${system?.hostname || "this node"}`}>
              <span className={`status-dot ${system?.docker ? "running" : "warning"}`} />
              {runtime}
            </span>
            <div className="notif-menu" ref={notifRef}>
              <button
                type="button"
                className={`icon-btn notif-trigger ${unread ? "has-unread" : ""}`}
                onClick={() => setNotifOpen((open) => !open)}
                aria-label={`Notifications${unread ? `, ${unread} unread` : ""}`}
                aria-haspopup="menu"
                aria-expanded={notifOpen}
              >
                <Icon name="bell" />
                {unread > 0 && <span className="notif-count">{unread > 9 ? "9+" : unread}</span>}
              </button>
              {notifOpen && (
                <div className="notif-pop" role="menu">
                  <div className="notif-head">
                    <div>
                      <strong>Notifications</strong>
                      <span>{unread ? `${unread} unread` : "Everything read"}</span>
                    </div>
                    {unread > 0 && (
                      <button type="button" onClick={markAllRead}>
                        <Icon name="check-double" /> Mark all read
                      </button>
                    )}
                  </div>
                  <div className="notif-list">
                    {notifications.map((item) => (
                      <div className={`notif-item severity-${item.severity} ${item.read ? "is-read" : ""}`} key={item.id}>
                        <span className="notif-icon">
                          <Icon
                            name={
                              item.kind === "plan_expiry"
                                ? "calendar-xmark"
                                : item.kind === "cpu"
                                  ? "microchip"
                                  : item.kind === "disk"
                                    ? "hard-drive"
                                    : "circle-info"
                            }
                          />
                        </span>
                        <div className="notif-copy">
                          <strong>{item.title}</strong>
                          <span>{item.body}</span>
                          <em>
                            {timeAgo(item.created_at)}
                            {item.server_id && (
                              <Link to={`/server/${item.server_id}`} onClick={() => setNotifOpen(false)}>
                                Open server
                              </Link>
                            )}
                            {item.kind === "plan_expiry" && (
                              <Link to="/billing" onClick={() => setNotifOpen(false)}>
                                Renew plan
                              </Link>
                            )}
                          </em>
                        </div>
                        {!item.read && <i className="notif-dot" aria-hidden="true" />}
                      </div>
                    ))}
                    {!notifications.length && (
                      <div className="notif-empty">
                        <Icon name="bell-slash" />
                        <span>No alerts yet. Plan expiry, CPU and disk warnings will appear here.</span>
                      </div>
                    )}
                  </div>
                  <Link className="notif-foot" to="/account" onClick={() => setNotifOpen(false)}>
                    Manage alert thresholds <Icon name="arrow-right" />
                  </Link>
                </div>
              )}
            </div>
            {admin && (
              <Link to="/admin/servers/new" className="btn btn-primary btn-sm">
                <Icon name="plus" /> New server
              </Link>
            )}
            <div className="user-menu" ref={userMenuRef}>
              <button
                type="button"
                className="user-trigger"
                onClick={() => setUserMenu((open) => !open)}
                aria-haspopup="menu"
                aria-expanded={userMenu}
              >
                <span className="avatar">{initials}</span>
                <span className="user-meta">
                  <strong>{displayName}</strong>
                  <small>{admin ? "Administrator" : "Member"}</small>
                </span>
                <Icon name="chevron-down" className="user-chevron" />
              </button>
              {userMenu && (
                <div className="user-pop" role="menu">
                  <div className="user-pop-head">
                    <span className="avatar avatar-lg">{initials}</span>
                    <div>
                      <strong>{displayName}</strong>
                      <small>{user.email}</small>
                    </div>
                  </div>
                  <Link to="/account" role="menuitem">
                    <Icon name="user-gear" /> Account settings
                  </Link>
                  {admin && (
                    <Link to="/admin/settings" role="menuitem">
                      <Icon name="sliders" /> Panel settings
                    </Link>
                  )}
                  <button type="button" role="menuitem" onClick={logout}>
                    <Icon name="arrow-right-from-bracket" /> Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>
        <main className="content">
          <Outlet
            context={{
              user,
              system,
              refreshUser: async () => {
                const next = await refreshUser();
                onUserChange(next);
                return next;
              },
            }}
          />
        </main>
      </div>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} admin={admin} />
    </div>
  );
}
