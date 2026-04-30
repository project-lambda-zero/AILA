import { useEffect, useState } from "react";

import Particles, { initParticlesEngine } from "@tsparticles/react";
import { loadSlim } from "@tsparticles/slim";

/**
 * Particle background for the login page left panel.
 *
 * Code-split via React.lazy() in LoginPage.tsx to avoid bundling
 * tsparticles on every page load.
 *
 * Reads --color-accent from CSS custom properties so particles
 * adapt to the active theme (synthwave=pink, vaporwave=rose, aero=blue).
 */

function getAccentColor(): string {
  if (typeof window === "undefined") return "#ff2d95";
  const raw = getComputedStyle(document.documentElement)
    .getPropertyValue("--color-accent")
    .trim();
  return raw || "#ff2d95";
}

export function LoginParticles() {
  const [engineReady, setEngineReady] = useState(false);
  const [accentColor] = useState(getAccentColor);

  useEffect(() => {
    initParticlesEngine(async (engine) => {
      await loadSlim(engine);
    })
      .then(() => setEngineReady(true))
      .catch(() => {
        // Silently fail — particles are decorative, not functional
      });
  }, []);

  if (!engineReady) return null;

  return (
    <Particles
      className="absolute inset-0"
      id="login-particles"
      options={{
        fullScreen: { enable: false },
        detectRetina: true,
        fpsLimit: 30,
        particles: {
          number: { value: 40, density: { enable: true } },
          color: { value: accentColor },
          opacity: { value: 0.15 },
          size: { value: { min: 1, max: 2 } },
          move: {
            enable: true,
            speed: 0.4,
            direction: "none",
            random: true,
            straight: false,
            outModes: { default: "bounce" },
          },
          links: {
            enable: true,
            distance: 120,
            color: accentColor,
            opacity: 0.08,
            width: 1,
          },
        },
        interactivity: {
          events: {
            onHover: { enable: false },
            onClick: { enable: false },
          },
        },
      }}
    />
  );
}
