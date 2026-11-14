import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { api, type Server } from "../api";
import { Icon } from "../icons";

type Command = {
  id: string;
  label: string;
  hint?: string;
  group: string;
  icon: string;
  to: string;
  keywords?: string;
};

const WORKSPACE: Command[] = [
  { id: "overview", label: "Overview", hint: "Control center and live telemetry", group: "Workspace", icon: "gauge-high", to: "/", keywords: "home dashboard control center" },
  { id: "billing", label: "Plans & billing", hint: "Plans, orders and redeem codes", group: "Workspace", icon: "layer-group", to: "/billing", keywords: "renew upgrade payment invoice order" },
  { id: "account", label: "Account", hint: "Profile, security and alert thresholds", group: "Workspace", icon: "user-gear", to: "/account", keywords: "password two factor alerts notifications settings" },
];

const ADMIN: Command[] = [
  { id: "admin", label: "Administration", hint: "Sales, fleet and panel overview", group: "Administration", icon: "chart-pie", to: "/admin", keywords: "admin dashboard revenue sales" },
  { id: "admin-servers", label: "Servers", hint: "Every workload on the panel", group: "Administration", icon: "server", to: "/admin/servers", keywords: "instances workloads" },
  { id: "admin-commerce", label: "Commerce", hint: "Plans, payments, orders and codes", group: "Administration", icon: "receipt", to: "/admin/commerce", keywords: "billing pricing redeem" },
  { id: "admin-safety", label: "Safety", hint: "Rules, strikes and enforcement", group: "Administration", icon: "shield-halved", to: "/admin/safety", keywords: "security policy abuse" },
  { id: "admin-nodes", label: "Nodes", hint: "Fleet, allocations and installers", group: "Administration", icon: "network-wired", to: "/admin/nodes", keywords: "daemon wings location allocation" },
  { id: "admin-locations", label: "Locations", hint: "Regions and country metadata", group: "Administration", icon: "location-dot", to: "/admin/locations", keywords: "region country" },
  { id: "admin-nests", label: "Nests & eggs", hint: "Runtime templates and startup", group: "Administration", icon: "layer-group", to: "/admin/nests", keywords: "egg template runtime" },
  { id: "admin-users", label: "Users", hint: "Accounts, roles and subusers", group: "Administration", icon: "users", to: "/admin/users", keywords: "members admin account" },
  { id: "admin-databases", label: "Database hosts", hint: "MySQL and MariaDB capacity", group: "Administration", icon: "database", to: "/admin/databases", keywords: "mysql mariadb" },
  { id: "admin-system", label: "System health", hint: "Host, runtime and storage", group: "Administration", icon: "heart-pulse", to: "/admin/system", keywords: "health metrics cpu memory disk" },
  { id: "admin-activity", label: "Audit log", hint: "Every recorded panel action", group: "Administration", icon: "clock-rotate-left", to: "/admin/activity", keywords: "events history log" },
  { id: "admin-settings", label: "Settings", hint: "Branding, registration and defaults", group: "Administration", icon: "sliders", to: "/admin/settings", keywords: "panel configuration" },
];

export default function CommandPalette({
  open,
  onClose,
  admin,
}: {
  open: boolean;
  onClose: () => void;
  admin: boolean;
}) {
  const nav = useNavigate();
  const [query, setQuery] = useState("");
  const [servers, setServers] = useState<Server[]>([]);
  const [loading, setLoading] = useState(false);
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    previousFocus.current = document.activeElement as HTMLElement | null;
    setQuery("");
    setActive(0);
    setLoading(true);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const timer = window.setTimeout(() => inputRef.current?.focus(), 40);
    api
      .servers()
      .then((response) => setServers(response.data))
      .catch(() => setServers([]))
      .finally(() => setLoading(false));
    return () => {
      window.clearTimeout(timer);
      document.body.style.overflow = overflow;
      previousFocus.current?.focus?.();
    };
  }, [open]);

  const commands = useMemo<Command[]>(() => {
    const list = [...WORKSPACE];
    if (admin) list.push(...ADMIN);
    if (admin) {
      list.push({
        id: "action-new-server",
        label: "Provision a new server",
        hint: "Open the deployment wizard",
        group: "Actions",
        icon: "plus",
        to: "/admin/servers/new",
        keywords: "create deploy new workload",
      });
      list.push({
        id: "action-new-user",
        label: "Create a panel user",
        hint: "Invite a member or administrator",
        group: "Actions",
        icon: "user-plus",
        to: "/admin/users/new",
        keywords: "invite account member",
      });
    }
    servers.forEach((server) => {
      list.push({
        id: `server-${server.id}`,
        label: server.name,
        hint: `${server.nest_name} / ${server.egg_name} · ${server.status}${server.suspended ? " · suspended" : ""}`,
        group: "Workloads",
        icon: "server",
        to: `/server/${server.id}`,
        keywords: `${server.identifier} ${server.owner_name} ${server.plan?.name || ""} ${(server.tags || []).join(" ")}`,
      });
    });
    return list;
  }, [admin, servers]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return commands;
    return commands.filter((command) =>
      `${command.label} ${command.hint || ""} ${command.group} ${command.keywords || ""}`
        .toLowerCase()
        .includes(needle)
    );
  }, [commands, query]);

  useEffect(() => {
    setActive(0);
  }, [query]);

  useEffect(() => {
    if (!open) return;
    const node = listRef.current?.querySelector<HTMLElement>(`[data-command-index="${active}"]`);
    node?.scrollIntoView({ block: "nearest" });
  }, [active, open]);

  const run = useCallback(
    (command: Command) => {
      onClose();
      nav(command.to);
    },
    [nav, onClose]
  );

  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key === "ArrowDown") {
        event.preventDefault();
        setActive((current) => Math.min(Math.max(filtered.length - 1, 0), current + 1));
        return;
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        setActive((current) => Math.max(0, current - 1));
        return;
      }
      if (event.key === "Enter" && filtered[active]) {
        event.preventDefault();
        run(filtered[active]);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, filtered, active, onClose, run]);

  if (!open) return null;

  return createPortal(
    <div
      className="command-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="command-panel" role="dialog" aria-modal="true" aria-label="Search the panel">
        <div className="command-search">
          <Icon name="magnifying-glass" />
          <input
            ref={inputRef}
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search pages, workloads or actions"
            aria-label="Search pages, workloads and actions"
            autoComplete="off"
          />
          <kbd>Esc</kbd>
        </div>

        <div className="command-results" ref={listRef} role="listbox" aria-label="Search results">
          {loading && (
            <div className="command-note">
              <Icon name="circle-notch" className="spin" /> Reading the fleet
            </div>
          )}
          {!loading && filtered.length === 0 && (
            <div className="command-empty">
              <Icon name="satellite-dish" />
              <strong>No orbit matches this search</strong>
              <span>Try a server name, page, owner or action.</span>
            </div>
          )}
          {filtered.map((command, index) => {
            const showGroup = index === 0 || filtered[index - 1].group !== command.group;
            return (
              <div key={command.id}>
                {showGroup && <span className="command-group-label">{command.group}</span>}
                <button
                  type="button"
                  role="option"
                  aria-selected={index === active}
                  data-command-index={index}
                  className={`command-item ${index === active ? "is-active" : ""}`}
                  onMouseEnter={() => setActive(index)}
                  onClick={() => run(command)}
                >
                  <span className="command-icon">
                    <Icon name={command.icon} />
                  </span>
                  <span className="command-copy">
                    <strong>{command.label}</strong>
                    {command.hint && <small>{command.hint}</small>}
                  </span>
                  <Icon name="arrow-turn-down" className="command-enter" />
                </button>
              </div>
            );
          })}
        </div>

        <div className="command-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> Navigate</span>
          <span><kbd>↵</kbd> Open</span>
          <span><kbd>Esc</kbd> Close</span>
          <span className="command-brand">Cosmos Molorum · quick console</span>
        </div>
      </div>
    </div>,
    document.body
  );
}
