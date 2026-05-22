import { Link } from "react-router";
import { User, Monitor, Info, ArrowRight, Palette, Sun, Moon } from "@phosphor-icons/react";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { useTheme, type Theme } from "@/providers/ThemeProvider";
import { appEnv } from "@platform/config/env";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ---------------------------------------------------------------------------
// Section card wrapper
// ---------------------------------------------------------------------------

function Section({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-surface p-6 space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-accent">{icon}</span>
        <h2 className="text-base font-semibold font-mono tracking-tight text-foreground">
          {title}
        </h2>
      </div>
      {children}
    </div>
  );
}

function ProfileRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-border last:border-0">
      <span className="text-sm text-text-muted">{label}</span>
      <span className="text-sm font-medium text-foreground">{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Theme preview — a mini rendering of what the theme looks like.
// Each theme renders a 180-high card that IS the theme, not just swatches.
// Inline styles are used so the preview is identical regardless of the
// currently-active theme (the preview should always show its OWN look).
// ---------------------------------------------------------------------------

type ThemeMeta = {
  label: string;
  tagline: string;
  naturalMode: "dark" | "light";
};

const THEME_META: Record<Theme, ThemeMeta> = {
  "midnight-cloud-8": {
    label: "Midnight Cloud 8",
    tagline: "Istanbul at dusk. Cream on charcoal, hot-pink halos.",
    naturalMode: "dark",
  },
  "frutiger-aero": {
    label: "Frutiger Aero",
    tagline: "Bliss sky + wet glass. 2006 is back.",
    naturalMode: "light",
  },
  synthwave: {
    label: "Synthwave",
    tagline: "1984 neon grid. Chromatic horizon.",
    naturalMode: "dark",
  },
  vaporwave: {
    label: "Vaporwave",
    tagline: "A E S T H E T I C. Win95 pastel mall.",
    naturalMode: "dark",
  },
  ps1: {
    label: "PlayStation 1",
    tagline: "Console-gray chassis. RGBY PS logo.",
    naturalMode: "light",
  },
  ps2: {
    label: "PlayStation 2",
    tagline: "Black + cyan. Rising boot cubes.",
    naturalMode: "dark",
  },
  "cyberpunk-2077": {
    label: "Cyberpunk 2077",
    tagline: "NCPD yellow / cyan / red. RGB slice.",
    naturalMode: "dark",
  },
  matrix: {
    label: "The Matrix",
    tagline: "Phosphor green rain on black.",
    naturalMode: "dark",
  },
  "truman-show": {
    label: "Truman Show",
    tagline: "Pastel dome. Hidden-camera vignette.",
    naturalMode: "light",
  },
  "half-life-1": {
    label: "Half-Life 1",
    tagline: "HEV orange. Black Mesa hazard bay.",
    naturalMode: "dark",
  },
  "y2k-fever": {
    label: "Y2K Fever",
    tagline: "Holographic chrome. iMac blueberry.",
    naturalMode: "light",
  },
  vendetta: {
    label: "Vendetta",
    tagline: "Blood-red on black. Remember remember.",
    naturalMode: "dark",
  },
};

function ThemePreview({ theme }: { theme: Theme }) {
  if (theme === "midnight-cloud-8") {
    return (
      <div
        className="relative h-28 overflow-hidden rounded-md"
        style={{ background: "#121212" }}
      >
        {/* Subtle horizontal scanlines — 1px every 3px, opacity 0.06 */}
        <div
          aria-hidden
          className="absolute inset-0"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, rgba(255,215,175,0.06) 0px, rgba(255,215,175,0.06) 1px, transparent 1px, transparent 3px)",
            mixBlendMode: "overlay",
          }}
        />
        {/* Dusk glow — soft pink wash at the bottom */}
        <div
          aria-hidden
          className="absolute inset-x-0 bottom-0"
          style={{
            height: "55%",
            background:
              "radial-gradient(ellipse 90% 100% at 50% 100%, rgba(255,95,135,0.32) 0%, rgba(240,168,199,0.16) 35%, transparent 70%)",
          }}
        />
        {/* Top hairline — transparent → accent → transparent (the techBorder cue) */}
        <div
          aria-hidden
          className="absolute inset-x-0 top-0 h-px"
          style={{
            background:
              "linear-gradient(90deg, transparent, rgba(255,95,135,0.6), transparent)",
          }}
        />
        {/* L-shaped corner brackets */}
        <div aria-hidden className="absolute top-1 left-1 h-3 w-3" style={{ borderTop: "2px solid rgba(255,95,135,0.55)", borderLeft: "2px solid rgba(255,95,135,0.55)" }} />
        <div aria-hidden className="absolute top-1 right-1 h-3 w-3" style={{ borderTop: "2px solid rgba(255,95,135,0.55)", borderRight: "2px solid rgba(255,95,135,0.55)" }} />
        <div aria-hidden className="absolute bottom-1 left-1 h-3 w-3" style={{ borderBottom: "2px solid rgba(255,95,135,0.55)", borderLeft: "2px solid rgba(255,95,135,0.55)" }} />
        <div aria-hidden className="absolute bottom-1 right-1 h-3 w-3" style={{ borderBottom: "2px solid rgba(255,95,135,0.55)", borderRight: "2px solid rgba(255,95,135,0.55)" }} />
        {/* Wordmark + tagline */}
        <div className="absolute left-3 top-3 right-3 flex flex-col gap-0.5">
          <div
            className="text-[14px] font-bold tracking-tight"
            style={{
              color: "#ffd7af",
              fontFamily: "'Bricolage Grotesque', 'Geist', sans-serif",
              textShadow:
                "0 0 1px rgba(255,95,135,0.6), 0 0 18px rgba(255,95,135,0.45)",
            }}
          >
            AILA
          </div>
          <div
            className="text-[9px]"
            style={{
              color: "#f0a8c7",
              fontFamily: "'Cascadia Mono', 'Cascadia Code', monospace",
              letterSpacing: "0.08em",
            }}
          >
            MIDNIGHT/CLOUD/8
          </div>
        </div>
        {/* Cream-outlined button — the theme's button style */}
        <div
          className="absolute right-3 bottom-2 text-[9px] font-medium px-2 py-0.5"
          style={{
            color: "#ffd7af",
            border: "1px solid #ffd7af",
            fontFamily: "'Cascadia Mono', 'Cascadia Code', monospace",
            letterSpacing: "0.04em",
          }}
        >
          ENTER
        </div>
      </div>
    );
  }

  if (theme === "frutiger-aero") {
    return (
      <div
        className="relative h-28 overflow-hidden rounded-md"
        style={{
          background:
            "radial-gradient(ellipse at top, rgba(135, 206, 250, 0.6) 0%, transparent 60%)," +
            "radial-gradient(ellipse at bottom right, rgba(152, 251, 152, 0.5) 0%, transparent 60%)," +
            "linear-gradient(180deg, #bfe4fc 0%, #e8f4fc 100%)",
        }}
      >
        {/* Bokeh droplets */}
        <div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(circle at 20% 30%, rgba(74,144,217,0.45) 0%, transparent 6%)," +
              "radial-gradient(circle at 70% 60%, rgba(42,157,110,0.35) 0%, transparent 8%)," +
              "radial-gradient(circle at 85% 25%, rgba(124,95,181,0.3) 0%, transparent 5%)",
            filter: "blur(1px)",
          }}
        />
        {/* Glass card */}
        <div
          className="absolute left-3 top-3 right-3 bottom-3 rounded-md flex flex-col justify-between p-2"
          style={{
            background:
              "linear-gradient(180deg, rgba(255,255,255,0.85) 0%, rgba(245,250,255,0.65) 100%)",
            backdropFilter: "blur(10px)",
            WebkitBackdropFilter: "blur(10px)",
            boxShadow:
              "0 1px 0 rgba(255,255,255,0.95) inset, 0 -1px 0 rgba(200,214,229,0.5) inset, 0 4px 12px rgba(74,144,217,0.18)",
            border: "1px solid rgba(200,214,229,0.6)",
          }}
        >
          <div
            className="text-[11px] font-semibold"
            style={{ color: "#1a2030", fontFamily: "Syne, sans-serif" }}
          >
            AILA
          </div>
          {/* Glossy pill button */}
          <div
            className="self-start text-[9px] font-semibold px-3 py-1"
            style={{
              borderRadius: "999px",
              background:
                "linear-gradient(180deg, #7cc5f5 0%, #4a90d9 50%, #2e78c1 100%)",
              color: "#ffffff",
              boxShadow:
                "0 1px 0 rgba(255,255,255,0.7) inset, 0 -1px 0 rgba(0,0,0,0.15) inset, 0 2px 6px rgba(74,144,217,0.5)",
              backgroundImage:
                "linear-gradient(180deg, rgba(255,255,255,0.6) 0%, rgba(255,255,255,0) 50%, rgba(0,0,0,0.1) 100%), linear-gradient(180deg, #7cc5f5 0%, #4a90d9 100%)",
            }}
          >
            Run Scan
          </div>
        </div>
      </div>
    );
  }

  if (theme === "synthwave") {
    return (
      <div
        className="relative h-28 overflow-hidden rounded-md"
        style={{
          background:
            "radial-gradient(circle 110px at 50% 100%, #ffaa44 0%, #ff4488 25%, #ff2d95 45%, transparent 65%)," +
            "linear-gradient(180deg, #070714 0%, #0f0f28 40%, #2a0a40 70%, #1a0a28 100%)",
        }}
      >
        {/* Perspective grid floor */}
        <div
          className="absolute inset-x-0 bottom-0"
          style={{
            height: "55%",
            background:
              "repeating-linear-gradient(0deg, transparent 0, transparent 10px, rgba(0,240,255,0.6) 10px, rgba(0,240,255,0.6) 11px)," +
              "repeating-linear-gradient(90deg, transparent 0, transparent 10px, rgba(255,45,149,0.4) 10px, rgba(255,45,149,0.4) 11px)",
            transform: "perspective(120px) rotateX(55deg)",
            transformOrigin: "center top",
            opacity: 0.55,
          }}
        />
        {/* Chromatic heading */}
        <div className="absolute left-3 top-2 right-3">
          <div
            className="text-[13px] font-bold tracking-wider"
            style={{
              color: "#e2e0ff",
              fontFamily: "Syne, sans-serif",
              textShadow: "-1px 0 #00f0ff, 1px 0 #ff2d95, 0 0 6px rgba(255,45,149,0.5)",
            }}
          >
            AILA
          </div>
          <div
            className="text-[9px]"
            style={{
              color: "#00f0ff",
              fontFamily: "Space Grotesk, sans-serif",
              textShadow: "0 0 4px rgba(0,240,255,0.6)",
            }}
          >
            NEON RUNTIME
          </div>
        </div>
        {/* Neon outline button */}
        <div
          className="absolute right-3 bottom-2 text-[9px] font-semibold px-2 py-0.5"
          style={{
            color: "#ff2d95",
            border: "1.5px solid #ff2d95",
            textShadow: "0 0 4px rgba(255,45,149,0.8)",
            boxShadow:
              "0 0 8px rgba(255,45,149,0.5), inset 0 0 6px rgba(255,45,149,0.2)",
            background: "transparent",
          }}
        >
          DRIVE
        </div>
      </div>
    );
  }

  if (theme === "vaporwave") {
    return (
      <div
        className="relative h-28 overflow-hidden rounded-md"
        style={{
          background:
            "linear-gradient(180deg, #1a1528 0%, #2a1540 40%, #3d1e50 70%, #1f0f30 100%)",
        }}
      >
        <div
          className="absolute inset-x-0 bottom-0"
          style={{
            height: "55%",
            background:
              "linear-gradient(45deg, rgba(240,168,199,0.25) 25%, transparent 25%, transparent 75%, rgba(240,168,199,0.25) 75%)," +
              "linear-gradient(45deg, rgba(126,200,200,0.25) 25%, transparent 25%, transparent 75%, rgba(126,200,200,0.25) 75%)",
            backgroundSize: "16px 16px",
            backgroundPosition: "0 0, 8px 8px",
            transform: "perspective(120px) rotateX(55deg)",
            transformOrigin: "center top",
            opacity: 0.7,
          }}
        />
        <div
          className="absolute left-3 top-3 right-3 bottom-3 flex flex-col justify-between p-2"
          style={{
            background: "#2e2848",
            boxShadow:
              "-2px -2px 0 #f8d0e4 inset, 2px 2px 0 #1a0a28 inset, -1px -1px 0 #fff0f5 inset, 1px 1px 0 #0a0015 inset",
            border: "1px solid #3d3660",
          }}
        >
          <div className="flex items-center justify-between">
            <div
              className="text-[10px] font-bold tracking-widest"
              style={{
                color: "#ffe8f5",
                fontFamily: "Syne, sans-serif",
                textShadow: "0 0 4px rgba(26,10,40,0.8), -1px 0 rgba(240,168,199,0.6)",
                letterSpacing: "0.2em",
              }}
            >
              A I L A
            </div>
            <div className="text-[9px]" style={{ color: "#d7afd7", fontFamily: "serif" }}>
              エアロ
            </div>
          </div>
          <div
            className="self-start text-[9px] font-semibold px-3 py-0.5"
            style={{
              background: "#f0a8c7",
              color: "#1a0a28",
              borderRadius: "0",
              boxShadow:
                "inset 1px 1px 0 #fff0f5, inset -1px -1px 0 #1a0a28, inset 2px 2px 0 #ffc8dd, inset -2px -2px 0 #5a3060",
              textShadow: "0 1px 0 rgba(255,255,255,0.3)",
            }}
          >
            START
          </div>
        </div>
      </div>
    );
  }

  if (theme === "ps1") {
    return (
      <div
        className="relative h-28 overflow-hidden"
        style={{ background: "linear-gradient(180deg,#d8d7d2 0%,#b0aeaa 100%)" }}
      >
        <div
          className="absolute inset-0"
          style={{
            background:
              "repeating-linear-gradient(0deg, transparent 0 3px, rgba(0,0,0,0.025) 3px 4px)",
          }}
        />
        <div
          className="absolute right-2 bottom-2"
          style={{
            width: 56, height: 56,
            backgroundImage:
              "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 200'><rect x='20' y='20' width='70' height='70' fill='%23e41e26'/><rect x='110' y='20' width='70' height='70' fill='%2300a651'/><rect x='20' y='110' width='70' height='70' fill='%232f6fbf'/><rect x='110' y='110' width='70' height='70' fill='%23f9b528'/><text x='100' y='110' text-anchor='middle' font-family='Michroma,sans-serif' font-size='28' font-weight='900' fill='%23ffffff'>PS</text></svg>\")",
            backgroundSize: "contain",
            backgroundRepeat: "no-repeat",
            filter: "drop-shadow(0 2px 4px rgba(0,0,0,0.2))",
          }}
        />
        <div
          className="absolute left-3 top-3 text-[12px] font-bold"
          style={{
            color: "#1a1a1a",
            fontFamily: "Michroma,Eurostile,sans-serif",
            letterSpacing: "0.15em",
            textShadow: "1px 1px 0 #fff, 2px 2px 0 #2f6fbf",
          }}
        >
          AILA
        </div>
        <div
          className="absolute left-3 bottom-3 text-[9px] px-3 py-0.5"
          style={{
            background: "linear-gradient(180deg,#b0b0ac 0%,#7f7e7a 100%)",
            color: "#1a1a1a",
            fontFamily: "Michroma,sans-serif",
            letterSpacing: "0.14em",
            boxShadow:
              "inset 1px 1px 0 #fff, inset -1px -1px 0 #3a3a36, inset 2px 2px 0 #d8d7d2, inset -2px -2px 0 #5a5a56",
          }}
        >
          START
        </div>
      </div>
    );
  }

  if (theme === "ps2") {
    return (
      <div
        className="relative h-28 overflow-hidden rounded-[2px]"
        style={{ background: "radial-gradient(ellipse at center,#001020 0%,#000 70%)" }}
      >
        <div
          className="absolute inset-0"
          style={{
            backgroundImage:
              "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='120' height='120'><g fill='none' stroke='%234fd8ff' stroke-width='1'><rect x='10' y='20' width='20' height='20' opacity='0.6'/><rect x='60' y='40' width='32' height='32' opacity='0.45'/><rect x='30' y='70' width='24' height='24' opacity='0.7'/><rect x='80' y='90' width='14' height='14' opacity='0.85'/></g></svg>\")",
            filter: "drop-shadow(0 0 6px rgba(79,216,255,0.4))",
          }}
        />
        <div
          className="absolute inset-0"
          style={{
            background:
              "repeating-linear-gradient(0deg, transparent 0 2px, rgba(79,216,255,0.04) 2px 3px)",
          }}
        />
        <div
          className="absolute left-3 top-3 text-[14px]"
          style={{
            color: "transparent",
            WebkitTextStroke: "1px #4fd8ff",
            fontFamily: "Iceberg, Bungee, Michroma, sans-serif",
            letterSpacing: "0.25em",
            filter: "drop-shadow(0 0 6px rgba(79,216,255,0.5))",
          }}
        >
          AILA
        </div>
        <div
          className="absolute right-3 bottom-3 text-[9px] px-2 py-0.5"
          style={{
            border: "1px solid #4fd8ff",
            color: "#4fd8ff",
            letterSpacing: "0.2em",
            textTransform: "uppercase",
            fontFamily: "Iceberg,Bungee,sans-serif",
            boxShadow: "0 0 10px rgba(79,216,255,0.4)",
          }}
        >
          Start
        </div>
      </div>
    );
  }

  if (theme === "cyberpunk-2077") {
    return (
      <div
        className="relative h-28 overflow-hidden"
        style={{ background: "#05070a" }}
      >
        <div
          className="absolute inset-0"
          style={{
            background:
              "repeating-linear-gradient(0deg,transparent 0 18px,rgba(252,238,10,0.1) 18px 19px)," +
              "repeating-linear-gradient(90deg,transparent 0 18px,rgba(0,240,255,0.09) 18px 19px)",
          }}
        />
        <div
          className="absolute left-3 top-3 text-[12px] font-bold"
          style={{
            color: "#fcee0a",
            fontFamily: "'Rubik Mono One',Bungee,sans-serif",
            letterSpacing: "0.04em",
            textShadow: "-2px 0 rgba(255,0,60,0.9),2px 0 rgba(0,240,255,0.9),0 0 10px rgba(252,238,10,0.55)",
          }}
        >
          AILA
        </div>
        <div
          className="absolute right-3 bottom-2 px-3 py-0.5 text-[9px]"
          style={{
            background: "#fcee0a",
            color: "#05070a",
            clipPath: "polygon(6px 0,100% 0,calc(100% - 6px) 100%,0 100%)",
            fontFamily: "'Rubik Mono One',Bungee,sans-serif",
            letterSpacing: "0.12em",
            boxShadow: "0 0 14px rgba(252,238,10,0.5)",
          }}
        >
          JACK IN
        </div>
      </div>
    );
  }

  if (theme === "matrix") {
    return (
      <div className="relative h-28 overflow-hidden" style={{ background: "#000" }}>
        <div
          className="absolute inset-0"
          style={{
            backgroundImage:
              "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='120' height='220'><g font-family='VT323,monospace' font-size='16'><text x='6' y='22' fill='%2300ff41'>0</text><text x='6' y='44' fill='%2300cc33' opacity='0.8'>ｱ</text><text x='6' y='66' fill='%23009922' opacity='0.6'>1</text><text x='32' y='36' fill='%2300ff41'>ﾂ</text><text x='32' y='60' fill='%2300aa2b'>0</text><text x='64' y='28' fill='%2300ff41'>ｵ</text><text x='64' y='52' fill='%2300cc33' opacity='0.8'>7</text><text x='90' y='20' fill='%2300ff41'>ﾘ</text><text x='90' y='46' fill='%2300cc33' opacity='0.7'>3</text></g></svg>\")",
            backgroundRepeat: "repeat",
            opacity: 0.9,
          }}
        />
        <div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.6) 100%)",
          }}
        />
        <div
          className="absolute left-3 top-3 text-[14px]"
          style={{
            color: "#00ff41",
            fontFamily: "'VT323','Share Tech Mono',monospace",
            letterSpacing: "0.1em",
            textShadow: "0 0 4px rgba(0,255,65,0.9),0 0 12px rgba(0,255,65,0.4)",
          }}
        >
          AILA
        </div>
        <div
          className="absolute right-3 bottom-2 px-2 py-0.5 text-[9px]"
          style={{
            border: "1px solid #00ff41",
            color: "#00ff41",
            fontFamily: "'VT323',monospace",
            textShadow: "0 0 5px rgba(0,255,65,0.6)",
            boxShadow: "0 0 8px rgba(0,255,65,0.4)",
          }}
        >
          WAKE UP
        </div>
      </div>
    );
  }

  if (theme === "truman-show") {
    return (
      <div
        className="relative h-28 overflow-hidden rounded-md"
        style={{
          background:
            "radial-gradient(circle 80px at 85% 10%,rgba(255,245,210,0.85) 0%,transparent 55%)," +
            "linear-gradient(180deg,#bee0e5 0%,#d5ebed 40%,#ecf6f2 70%,#b6d9b3 100%)",
        }}
      >
        <div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(circle at 3% 3%,rgba(10,20,22,0.3) 0%,transparent 22%)," +
              "radial-gradient(circle at 97% 97%,rgba(10,20,22,0.3) 0%,transparent 22%)",
          }}
        />
        <div
          className="absolute left-3 top-3 text-[12px]"
          style={{
            color: "#2a3b40",
            fontFamily: "'Marcellus SC','IM Fell English SC',serif",
            letterSpacing: "0.12em",
          }}
        >
          A I L A
        </div>
        <div
          className="absolute right-3 top-3"
          style={{ width: 14, height: 14, borderRadius: "50%", background: "rgba(20,40,40,0.55)", boxShadow: "0 0 0 2px rgba(255,253,244,0.8)" }}
        />
        <div
          className="absolute right-3 top-3"
          style={{ width: 4, height: 4, borderRadius: "50%", background: "#ffd966", transform: "translate(-5px,5px)" }}
        />
        <div
          className="absolute left-3 bottom-2 px-3 py-0.5 text-[9px]"
          style={{
            background: "linear-gradient(180deg,#5fbac2 0%,#4fa8b0 50%,#3f9198 100%)",
            color: "#fffdf4",
            letterSpacing: "0.12em",
            fontFamily: "'Marcellus SC',serif",
            borderRadius: 4,
            boxShadow: "inset 0 1px 0 rgba(255,253,244,0.55),0 2px 4px rgba(42,59,64,0.18)",
          }}
        >
          GOOD MORNING
        </div>
      </div>
    );
  }

  if (theme === "half-life-1") {
    return (
      <div
        className="relative h-28 overflow-hidden"
        style={{ background: "linear-gradient(180deg,#0c0d0f 0%,#121316 60%,#181a1e 100%)" }}
      >
        <div
          className="absolute inset-0"
          style={{
            background:
              "repeating-linear-gradient(0deg,transparent 0 3px,rgba(255,255,255,0.015) 3px 4px)",
          }}
        />
        <div
          className="absolute right-2 top-2"
          style={{
            width: 52, height: 52,
            backgroundImage:
              "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 200'><g fill='none' stroke='%23f9a31b' stroke-width='12' opacity='0.45'><path d='M 50 50 L 100 160 L 150 50'/><path d='M 70 95 L 130 95' stroke-width='11'/></g></svg>\")",
            backgroundSize: "contain",
            backgroundRepeat: "no-repeat",
          }}
        />
        <div
          className="absolute left-3 top-3 text-[12px] font-bold"
          style={{
            color: "#f9a31b",
            fontFamily: "'Bank Gothic Medium','Michroma',sans-serif",
            letterSpacing: "0.22em",
            textShadow: "0 0 2px rgba(249,163,27,0.7),0 0 10px rgba(249,163,27,0.35)",
          }}
        >
          AILA
        </div>
        <div
          className="absolute left-3 bottom-2 px-3 py-0.5 text-[9px]"
          style={{
            background: "linear-gradient(180deg,#fdb544 0%,#f9a31b 55%,#c47e0e 100%)",
            color: "#0f1012",
            fontFamily: "'Bank Gothic Medium',sans-serif",
            letterSpacing: "0.22em",
            border: "1px solid #a86a0a",
            boxShadow: "inset 0 1px 0 rgba(255,255,255,0.4),inset 0 -1px 0 rgba(0,0,0,0.35)",
            textShadow: "0 1px 0 rgba(255,255,255,0.3)",
          }}
        >
          NEW GAME
        </div>
      </div>
    );
  }

  if (theme === "y2k-fever") {
    return (
      <div
        className="relative h-28 overflow-hidden rounded-[18px]"
        style={{
          background:
            "linear-gradient(135deg,#ffdef2 0%,#cfeefb 30%,#d9ffe8 60%,#fff1cf 85%,#ffd6f0 100%)",
          backgroundSize: "200% 200%",
        }}
      >
        <div
          className="absolute"
          style={{
            right: 6, top: 6, width: 60, height: 60,
            backgroundImage:
              "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 200'><defs><radialGradient id='d' cx='50%25' cy='50%25' r='50%25'><stop offset='0%25' stop-color='%23ffffff'/><stop offset='40%25' stop-color='%23ff9acc'/><stop offset='60%25' stop-color='%23a0d8f5'/><stop offset='75%25' stop-color='%23ffd96b'/><stop offset='90%25' stop-color='%23b7ff8a'/><stop offset='100%25' stop-color='%23ff6fb3'/></radialGradient></defs><circle cx='100' cy='100' r='92' fill='url(%23d)' opacity='0.9'/><circle cx='100' cy='100' r='26' fill='%23fff'/><circle cx='100' cy='100' r='7' fill='%2355477e'/></svg>\")",
            backgroundSize: "contain",
            backgroundRepeat: "no-repeat",
            transform: "rotate(-18deg)",
            filter: "drop-shadow(0 3px 8px rgba(0,0,0,0.18))",
          }}
        />
        <div
          className="absolute left-3 top-3 text-[14px] font-bold"
          style={{
            fontFamily: "'Bungee','Audiowide',sans-serif",
            background: "linear-gradient(90deg,#ff5fb1,#ffa836,#baff3d,#5fc0d6,#c39aff)",
            WebkitBackgroundClip: "text",
            backgroundClip: "text",
            WebkitTextFillColor: "transparent",
            filter: "drop-shadow(0 1px 0 rgba(255,255,255,0.9))",
          }}
        >
          AILA
        </div>
        <div
          className="absolute left-3 bottom-3 px-3 py-0.5 text-[9px]"
          style={{
            borderRadius: 999,
            background:
              "linear-gradient(180deg,rgba(255,255,255,0.85) 0%,rgba(255,255,255,0) 48%,rgba(0,0,0,0.08) 100%),linear-gradient(180deg,#ff8bc7 0%,#ff5fb1 55%,#d43d91 100%)",
            color: "#fff",
            fontFamily: "'Bungee',sans-serif",
            border: "1.5px solid rgba(212,61,145,0.85)",
            boxShadow: "inset 0 2px 0 rgba(255,255,255,0.6),0 4px 10px rgba(255,95,177,0.4)",
          }}
        >
          LAUNCH
        </div>
      </div>
    );
  }

  // vendetta
  return (
    <div
      className="relative h-28 overflow-hidden"
      style={{
        background:
          "radial-gradient(ellipse at 50% 130%,#6a0410 0%,#2e0208 30%,transparent 60%)," +
          "linear-gradient(180deg,#07040a 0%,#0a0408 100%)",
      }}
    >
      <div
        className="absolute"
        style={{
          right: 2, bottom: 2, width: 80, height: 80,
          backgroundImage:
            "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 200'><g transform='translate(100 120)' opacity='0.55'><path d='M 0 0 Q -60 -10 -80 -60 Q -75 -90 -40 -100 Q 0 -107 40 -100 Q 75 -90 80 -60 Q 60 -10 0 0 Z' fill='%23eae2d5'/><path d='M -35 -65 Q -20 -50 -10 -65 M 35 -65 Q 20 -50 10 -65' stroke='%230d0609' stroke-width='2' fill='none'/><path d='M -10 -30 L 0 -10 L 10 -30' stroke='%23d80e1d' stroke-width='2' fill='none'/></g></svg>\")",
          backgroundSize: "contain",
          backgroundRepeat: "no-repeat",
        }}
      />
      <div
        className="absolute left-3 top-3 text-[14px]"
        style={{
          color: "#d80e1d",
          fontFamily: "'UnifrakturMaguntia','IM Fell English SC',serif",
          textShadow: "2px 2px 0 #000,0 0 10px rgba(216,14,29,0.5)",
        }}
      >
        AILA
      </div>
      <div
        className="absolute left-3 bottom-3 px-3 py-0.5 text-[9px]"
        style={{
          background: "#d80e1d",
          color: "#eae2d5",
          letterSpacing: "0.3em",
          fontFamily: "'Special Elite',serif",
          textTransform: "uppercase",
          boxShadow: "3px 3px 0 #000",
        }}
      >
        RESIST
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function SettingsPage() {
  const { username, role, userId } = useAuthStore();
  const { theme, mode, setTheme, toggleMode, isDark, themes } = useTheme();

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold font-mono tracking-tight text-foreground">
          Settings
        </h1>
        <p className="text-text-muted text-sm mt-1">
          Manage your profile, sessions, and appearance.
        </p>
      </div>

      {/* Profile */}
      <Section icon={<User size={18} />} title="Profile">
        <div>
          <ProfileRow label="Username" value={username ?? "\u2014"} />
          <ProfileRow
            label="Role"
            value={
              <Badge variant="outline" className="capitalize text-xs font-mono">
                {role ?? "\u2014"}
              </Badge>
            }
          />
          <ProfileRow
            label="User ID"
            value={
              <span className="font-mono text-xs text-text-muted">
                {userId ?? "\u2014"}
              </span>
            }
          />
        </div>
        <p className="text-xs text-text-muted">
          Contact your administrator to change your role or username.
        </p>
      </Section>

      {/* Sessions */}
      <Section icon={<Monitor size={18} />} title="Sessions">
        <p className="text-sm text-text-muted">
          Review and revoke active login sessions across all your devices.
        </p>
        <Link
          to="/settings/sessions"
          className="inline-flex items-center gap-2 text-sm text-accent hover:text-accent/80 font-medium transition-colors"
        >
          Manage active sessions
          <ArrowRight size={14} />
        </Link>
      </Section>

      {/* Theme */}
      <Section icon={<Palette size={18} />} title="Appearance">
        <p className="text-xs text-text-muted -mt-1">
          Eleven themes. Each its own era. Click a preview to switch.
        </p>

        {/* Mode toggle */}
        <div className="flex items-center justify-between pb-3 border-b border-border">
          <div>
            <p className="text-sm font-medium text-foreground">Mode</p>
            <p className="text-xs text-text-muted mt-0.5">
              Currently <span className="font-mono">{mode}</span>
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={toggleMode} className="gap-2">
            {isDark ? <Sun size={14} /> : <Moon size={14} />}
            {isDark ? "Light" : "Dark"}
          </Button>
        </div>

        {/* Theme picker — mini previews rendered in each theme's actual style */}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {themes.map((key) => {
            const meta = THEME_META[key];
            const active = theme === key;
            return (
              <button
                key={key}
                type="button"
                onClick={() => setTheme(key)}
                aria-label={`Switch to ${meta.label} theme`}
                aria-pressed={active}
                className={`group flex flex-col gap-2 p-2 rounded-md border transition-all text-left cursor-pointer ${
                  active
                    ? "border-accent ring-2 ring-accent/40 shadow-lg"
                    : "border-border hover:border-border-hover"
                }`}
              >
                <ThemePreview theme={key} />
                <div className="px-1 pt-0.5 pb-1">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-semibold text-foreground leading-tight">
                      {meta.label}
                    </p>
                    {active && (
                      <span className="text-[10px] font-mono text-accent">
                        {"\u2713 ACTIVE"}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-text-muted leading-tight mt-0.5">
                    {meta.tagline}
                  </p>
                  <p className="text-[10px] font-mono text-text-muted/70 mt-1 uppercase tracking-wider">
                    Natural mode: {meta.naturalMode}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </Section>

      {/* About */}
      <Section icon={<Info size={18} />} title="About">
        <div>
          <ProfileRow label="Application" value="AILA \u2014 AI Lab Assistant" />
          <ProfileRow
            label="API Endpoint"
            value={
              <span className="font-mono text-xs text-text-muted">
                {appEnv.apiBaseUrl}
              </span>
            }
          />
        </div>
      </Section>
    </div>
  );
}
