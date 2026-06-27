// 176b theme verification -- captures one screenshot per theme by setting
// localStorage directly then navigating to the login page. No auth needed
// for the atmospheric signature check; the login screen renders all the
// decorative CSS we care about (body atmosphere, cards, buttons).
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

const OUT = resolve(process.cwd(), "../.planning/phases/176-operator-console-completion/176b-screenshots");
mkdirSync(OUT, { recursive: true });

const THEMES = [
  { id: "frutiger-aero", mode: "light" },
  { id: "synthwave", mode: "dark" },
  { id: "vaporwave", mode: "dark" },
];

const BASE = "http://localhost:3000";

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();

  // prime origin for localStorage
  await page.goto(BASE + "/login");
  await page.waitForLoadState("domcontentloaded");

  for (const t of THEMES) {
    await page.evaluate(
      ({ id, mode }) => {
        localStorage.setItem("aila-theme", id);
        localStorage.setItem("aila-mode", mode);
      },
      t,
    );
    await page.goto(BASE + "/login", { waitUntil: "networkidle" });
    // give atmospheric CSS (backdrop-filter, perspective grids) time to settle
    await page.waitForTimeout(1200);
    const file = resolve(OUT, `${t.id}-login.png`);
    await page.screenshot({ path: file, fullPage: false });
    console.log(`saved ${file}`);
  }

  // also capture the settings page in one theme to see the preview cards
  await page.evaluate(() => {
    localStorage.setItem("aila-theme", "synthwave");
    localStorage.setItem("aila-mode", "dark");
  });
  await page.goto(BASE + "/settings", { waitUntil: "networkidle" });
  await page.waitForTimeout(1200);
  const settingsFile = resolve(OUT, `settings-theme-picker.png`);
  await page.screenshot({ path: settingsFile, fullPage: true });
  console.log(`saved ${settingsFile}`);

  await browser.close();
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
