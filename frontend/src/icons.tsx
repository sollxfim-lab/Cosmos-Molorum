import type { HTMLAttributes } from "react";
import dotnetLogo from "./assets/logos/dotnet.svg";
import goLogo from "./assets/logos/go.svg";
import javaLogo from "./assets/logos/java.svg";
import nodeLogo from "./assets/logos/node.svg";
import phpLogo from "./assets/logos/php.svg";
import pythonLogo from "./assets/logos/python.svg";
import rubyLogo from "./assets/logos/ruby.svg";
import rustLogo from "./assets/logos/rust.svg";

type IconProps = HTMLAttributes<HTMLElement> & {
  name: string;
  solid?: boolean;
  brand?: boolean;
};

/** Font Awesome icon wrapper. Decorative by default; add aria-label when meaningful. */
export function Icon({ name, solid = true, brand = false, className = "", ...rest }: IconProps) {
  const prefix = brand ? "fa-brands" : solid ? "fa-solid" : "fa-regular";
  return <i className={`${prefix} fa-${name} ${className}`.trim()} aria-hidden="true" {...rest} />;
}

/** Observatory mark: a portal arch, orbit ring and four-point star. */
export function IconMark({ className = "" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <path d="M7 33.5h26" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path
        d="M12.2 33.5V19.2a7.8 7.8 0 0 1 15.6 0v14.3"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
      <path
        d="M16.4 33.5V19.8a3.6 3.6 0 0 1 7.2 0v13.7"
        stroke="currentColor"
        strokeWidth="1.1"
        strokeLinecap="round"
        opacity=".48"
      />
      <ellipse
        cx="20"
        cy="20.8"
        rx="16.3"
        ry="6.1"
        transform="rotate(-20 20 20.8)"
        stroke="currentColor"
        strokeWidth="1.35"
        opacity=".88"
      />
      <path
        d="M20 11.2c.8 4.6 2.5 6.4 7.1 7.2-4.6.8-6.3 2.6-7.1 7.2-.8-4.6-2.5-6.4-7.1-7.2 4.6-.8 6.3-2.6 7.1-7.2Z"
        fill="currentColor"
      />
      <circle cx="31.4" cy="10.6" r="1.05" fill="currentColor" opacity=".7" />
    </svg>
  );
}

export function BrandMark({ className = "" }: { className?: string }) {
  return (
    <span className={`brand-logo ${className}`.trim()}>
      <IconMark />
    </span>
  );
}

/** Ivory observatory crest used above the sign-in form. */
export function AuthEmblem({ className = "" }: { className?: string }) {
  return (
    <span className={`auth-emblem-art ${className}`.trim()} aria-hidden="true">
      <svg viewBox="0 0 96 96" fill="none">
        <defs>
          <linearGradient id="cosmosEmblemOrbit" x1="10" y1="52" x2="86" y2="44" gradientUnits="userSpaceOnUse">
            <stop stopColor="#eadcc2" stopOpacity=".16" />
            <stop offset=".42" stopColor="#f4eee2" />
            <stop offset="1" stopColor="#c9a66f" stopOpacity=".42" />
          </linearGradient>
          <radialGradient id="cosmosEmblemHalo" cx="0" cy="0" r="1" gradientTransform="translate(48 46) rotate(90) scale(42)" gradientUnits="userSpaceOnUse">
            <stop stopColor="#eadcc2" stopOpacity=".18" />
            <stop offset="1" stopColor="#eadcc2" stopOpacity="0" />
          </radialGradient>
          <filter id="cosmosEmblemGlow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="3.2" />
          </filter>
        </defs>

        <circle cx="48" cy="46" r="42" fill="url(#cosmosEmblemHalo)" />
        <circle cx="48" cy="48" r="40.5" stroke="#eadcc2" strokeOpacity=".16" strokeWidth=".9" strokeDasharray="2 5" />

        <path d="M27 78V42.5C27 30.9 36.4 21.5 48 21.5s21 9.4 21 21V78" stroke="#f4eee2" strokeWidth="2.6" strokeLinecap="round" />
        <path d="M34 78V43.4c0-7.7 6.3-14 14-14s14 6.3 14 14V78" stroke="#eadcc2" strokeOpacity=".34" strokeWidth="1.1" strokeLinecap="round" />
        <path d="M20 78h56" stroke="#f4eee2" strokeWidth="2.6" strokeLinecap="round" />
        <path d="M27 78v5M69 78v5" stroke="#f4eee2" strokeOpacity=".55" strokeWidth="1.6" strokeLinecap="round" />

        <ellipse cx="48" cy="49" rx="40" ry="13.3" transform="rotate(-20 48 49)" stroke="url(#cosmosEmblemOrbit)" strokeWidth="2" />

        <g filter="url(#cosmosEmblemGlow)" opacity=".5">
          <path d="M48 27c1.3 8.2 4.8 11.7 13 13-8.2 1.3-11.7 4.8-13 13-1.3-8.2-4.8-11.7-13-13 8.2-1.3 11.7-4.8 13-13Z" fill="#eadcc2" />
        </g>
        <path d="M48 27c1.3 8.2 4.8 11.7 13 13-8.2 1.3-11.7 4.8-13 13-1.3-8.2-4.8-11.7-13-13 8.2-1.3 11.7-4.8 13-13Z" fill="#f4eee2" />

        <circle cx="74.5" cy="27.5" r="1.5" fill="#eadcc2" opacity=".75" />
        <circle cx="21.5" cy="59" r="1.15" fill="#c9a66f" opacity=".7" />
        <path d="M17 27.5h3M18.5 26v3M79 58h2.6M80.3 56.7v2.6" stroke="#eadcc2" strokeOpacity=".42" strokeWidth=".9" strokeLinecap="round" />
      </svg>
    </span>
  );
}

export type WorkloadKind =
  | "python"
  | "node"
  | "java"
  | "minecraft"
  | "bedrock"
  | "php"
  | "ruby"
  | "go"
  | "rust"
  | "dotnet"
  | "database"
  | "web"
  | "generic";

export function workloadKind(name: string, eggId?: number): WorkloadKind {
  const value = (name || "").toLowerCase();
  if (eggId === 28 || value.includes("bedrock")) return "bedrock";
  if (eggId === 27 || value.includes("minecraft") || value.includes("paper") || value.includes("purpur") || value.includes("forge") || value.includes("fabric")) return "minecraft";
  if (value.includes("python") || value.includes("flask") || value.includes("django")) return "python";
  if (value.includes("node") || value.includes("javascript") || value.includes("next") || value.includes("react") || value.includes("bun")) return "node";
  if (value.includes("java") && !value.includes("javascript")) return "java";
  if (value.includes("php") || value.includes("laravel") || value.includes("wordpress")) return "php";
  if (value.includes("ruby") || value.includes("rails")) return "ruby";
  if (value.includes("golang") || value.includes(" go ") || value === "go" || value.includes("gitea")) return "go";
  if (value.includes("rust") || value.includes("cargo")) return "rust";
  if (value.includes("dotnet") || value.includes(".net") || value.includes("c#") || value.includes("aspnet")) return "dotnet";
  if (value.includes("mysql") || value.includes("maria") || value.includes("postgres") || value.includes("database") || value.includes("redis") || value.includes("mongo")) return "database";
  if (value.includes("nginx") || value.includes("apache") || value.includes("caddy") || value.includes("static") || value.includes("web") || value.includes("html")) return "web";
  return "generic";
}

/**
 * Official workload marks, imported as unmodified brand assets.
 * Sources: python.org, nodejs.org, go.dev, rust-lang.org, oracle.com/java,
 * php.net, ruby-lang.org and dotnet.microsoft.com. Only sizing, and a
 * monochrome ivory fill for the Rust gear on dark plates, are applied.
 */
const BRAND_WORKLOADS: Partial<
  Record<WorkloadKind, { src: string; width: number; height: number }>
> = {
  python: { src: pythonLogo, width: 28.9, height: 35 },
  node: { src: nodeLogo, width: 34, height: 34 },
  go: { src: goLogo, width: 37, height: 13.9 },
  rust: { src: rustLogo, width: 34, height: 34 },
  java: { src: javaLogo, width: 20.7, height: 38 },
  php: { src: phpLogo, width: 37, height: 20 },
  ruby: { src: rubyLogo, width: 34, height: 34 },
  dotnet: { src: dotnetLogo, width: 34, height: 34 },
};

/** Product-specific marks shown while choosing and running a workload. */
export function WorkloadLogo({
  name,
  eggId,
  size = 42,
  className = "",
}: {
  name: string;
  eggId?: number;
  size?: number;
  className?: string;
}) {
  const kind = workloadKind(name, eggId);
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 48 48",
    className: `workload-logo workload-logo-${kind} ${className}`.trim(),
    "aria-hidden": true as const,
  };
  const brand = BRAND_WORKLOADS[kind];
  if (brand) {
    return (
      <svg {...common}>
        <rect width="48" height="48" rx="12" fill="#0f1c27" />
        <image
          href={brand.src}
          x={(48 - brand.width) / 2}
          y={(48 - brand.height) / 2}
          width={brand.width}
          height={brand.height}
          preserveAspectRatio="xMidYMid meet"
        />
      </svg>
    );
  }
  if (kind === "minecraft") {
    return (
      <svg {...common}>
        <rect width="48" height="48" rx="12" fill="#1b2619" />
        <path d="M24 8 38 16v16L24 40 10 32V16L24 8Z" fill="#6f9f4f" />
        <path d="M10 16 24 24v16L10 32V16Z" fill="#3f6b33" />
        <path d="M38 16 24 24v16l14-8V16Z" fill="#547f3c" />
        <path d="M24 8 38 16l-14 8L10 16 24 8Z" fill="#8dbc66" />
        <path d="M17 24v7l4 2v-7l-4-2Zm10 2v7l4-2v-7l-4 2Z" fill="#2f5128" opacity=".85" />
      </svg>
    );
  }
  if (kind === "bedrock") {
    return (
      <svg {...common}>
        <rect width="48" height="48" rx="12" fill="#23201c" />
        <path d="M24 8 38 16v16L24 40 10 32V16L24 8Z" fill="#8c8578" />
        <path d="M10 16 24 24v16L10 32V16Z" fill="#5f5a50" />
        <path d="M38 16 24 24v16l14-8V16Z" fill="#746d61" />
        <path d="M24 8 38 16l-14 8L10 16 24 8Z" fill="#a8a193" />
        <path d="M16 22.5 24 27l8-4.5v5L24 32l-8-4.5v-5Z" fill="#3f3b34" opacity=".7" />
      </svg>
    );
  }
  if (kind === "database") {
    return (
      <svg {...common}>
        <rect width="48" height="48" rx="12" fill="#171f29" />
        <ellipse cx="24" cy="14" rx="12" ry="4.6" fill="#88a8c7" />
        <path d="M12 14v18c0 2.5 5.4 4.5 12 4.5s12-2 12-4.5V14c0 2.5-5.4 4.5-12 4.5S12 16.5 12 14Z" fill="#4c6c8a" />
        <ellipse cx="24" cy="23" rx="12" ry="4.2" fill="#6c90b0" opacity=".55" />
        <ellipse cx="24" cy="31.5" rx="12" ry="4.2" fill="#6c90b0" opacity=".4" />
      </svg>
    );
  }
  if (kind === "web") {
    return (
      <svg {...common}>
        <rect width="48" height="48" rx="12" fill="#1a2420" />
        <circle cx="24" cy="24" r="15" stroke="#85b89a" strokeWidth="1.6" />
        <path d="M9.5 24h29M24 9c4.2 4.2 6.2 9.4 6.2 15S28.2 34.8 24 39c-4.2-4.2-6.2-9.4-6.2-15S19.8 13.2 24 9Z" stroke="#85b89a" strokeWidth="1.4" />
        <path d="M13 16h22M13 32h22" stroke="#5f8f74" strokeWidth="1.2" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <rect width="48" height="48" rx="12" fill="#211d18" />
      <rect x="11" y="13" width="26" height="8" rx="2" fill="#c9a97a" />
      <rect x="11" y="24" width="26" height="8" rx="2" fill="#a4865c" />
      <circle cx="16" cy="17" r="1.4" fill="#3a2c1c" />
      <circle cx="16" cy="28" r="1.4" fill="#3a2c1c" />
      <path d="M31 17h2M31 28h2" stroke="#3a2c1c" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}
