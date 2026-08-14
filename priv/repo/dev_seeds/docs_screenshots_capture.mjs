// SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
//
// SPDX-License-Identifier: Apache-2.0

// Captures the guide screenshots from a dev server staged by
// docs_screenshots.exs, into priv/static/images/guide/. Dependency-free:
// plain Node (>= 22, for the built-in WebSocket) driving a headless Chrome
// over the DevTools protocol.
//
//     mix run priv/repo/dev_seeds/docs_screenshots.exs
//     node priv/repo/dev_seeds/docs_screenshots_capture.mjs
//
// See priv/repo/dev_seeds/README.md for the full workflow.

import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.BASE_URL ?? "http://localhost:4000";
const OUT = "priv/static/images/guide";
const CHROME =
  process.env.CHROME_BIN ??
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const VIEWPORT = { width: 1440, height: 1000, deviceScaleFactor: 2 };

const manifest = JSON.parse(
  await readFile(
    join(dirname(fileURLToPath(import.meta.url)), ".docs_screenshots_manifest.json"),
    "utf8",
  ),
);
const caseUrl = `/cases/${manifest.main_case_id}`;

// One entry per published screenshot. `scrollTo` scrolls the first h2/h3
// whose text contains the string into view before capturing; `height` clips
// the viewport; `evaluate` runs before the capture.
//
// The reports and users shots must show seeded data only, whatever else the
// local dev database holds: the queue is clipped to the first (just-seeded)
// report, and every non-mock account is dropped from the users table.
const shots = [
  { role: "supporter", path: "/cases", file: "case-board.png" },
  { role: "supporter", path: caseUrl, file: "case-workspace.png" },
  { role: "supporter", path: caseUrl, scrollTo: "Affected", file: "affected-packages.png" },
  { role: "poc", path: "/reports", file: "report-triage.png", height: 560 },
  {
    role: "poc",
    path: "/users",
    file: "user-management.png",
    evaluate: `
      [...document.querySelectorAll("tbody tr")]
        .filter((row) => !row.textContent.includes("Mock"))
        .forEach((row) => row.remove());
      const count = document.querySelectorAll("tbody tr").length;
      [...document.querySelectorAll("td, div, span, p")]
        .filter((el) => el.children.length === 0 && /^\\s*\\d+ users\\s*$/.test(el.textContent))
        .forEach((el) => (el.textContent = count + " users"));
    `,
  },
  { role: "none", path: caseUrl, file: "maintainer-view.png" },
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.listeners = [];
    ws.addEventListener("message", (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      } else if (msg.method) {
        this.listeners.forEach((listener) => listener(msg));
      }
    });
  }

  send(method, params = {}, sessionId = undefined) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }

  waitFor(method, sessionId) {
    return new Promise((resolve) => {
      const listener = (msg) => {
        if (msg.method === method && msg.sessionId === sessionId) {
          this.listeners.splice(this.listeners.indexOf(listener), 1);
          resolve(msg.params);
        }
      };
      this.listeners.push(listener);
    });
  }
}

const profile = await mkdtemp(join(tmpdir(), "varsel-shots-"));
const chrome = spawn(CHROME, [
  "--headless=new",
  "--remote-debugging-port=0",
  `--user-data-dir=${profile}`,
  "--no-first-run",
  "--hide-scrollbars",
  "about:blank",
]);

try {
  // Chrome publishes the picked port in the profile directory.
  let port;
  for (let attempt = 0; attempt < 50 && !port; attempt++) {
    await sleep(200);
    port = await readFile(join(profile, "DevToolsActivePort"), "utf8")
      .then((contents) => contents.split("\n")[0])
      .catch(() => undefined);
  }
  if (!port) throw new Error("Chrome did not publish a DevTools port");

  const { webSocketDebuggerUrl } = await fetch(
    `http://127.0.0.1:${port}/json/version`,
  ).then((response) => response.json());

  const ws = new WebSocket(webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve);
    ws.addEventListener("error", reject);
  });
  const cdp = new Cdp(ws);

  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });

  await cdp.send("Page.enable", {}, sessionId);
  await cdp.send("Emulation.setDeviceMetricsOverride", { ...VIEWPORT, mobile: false }, sessionId);

  const navigate = async (path) => {
    const loaded = cdp.waitFor("Page.loadEventFired", sessionId);
    await cdp.send("Page.navigate", { url: `${BASE}${path}` }, sessionId);
    await loaded;
    await sleep(1200); // LiveView connect + first patch
  };

  await mkdir(OUT, { recursive: true });

  let role;
  for (const shot of shots) {
    if (shot.role !== role) {
      await cdp.send("Network.clearBrowserCookies", {}, sessionId);
      await navigate(`/auth/user/mock/callback?role=${shot.role}`);
      role = shot.role;
    }

    await cdp.send(
      "Emulation.setDeviceMetricsOverride",
      { ...VIEWPORT, height: shot.height ?? VIEWPORT.height, mobile: false },
      sessionId,
    );

    await navigate(shot.path);

    const evaluate = async (expression) => {
      const { exceptionDetails } = await cdp.send("Runtime.evaluate", { expression }, sessionId);
      if (exceptionDetails) {
        throw new Error(`evaluate failed for ${shot.file}: ${exceptionDetails.text}`);
      }
    };

    if (shot.evaluate) {
      await evaluate(shot.evaluate);
      await sleep(200);
    }

    if (shot.scrollTo) {
      // One instant jump (the page's own scroll-behavior is smooth, and a
      // second scroll call would cancel a still-animating first one), offset
      // so the heading clears the sticky site header.
      await evaluate(`(() => {
        const heading = [...document.querySelectorAll("h2, h3")]
          .find((el) => el.textContent.includes(${JSON.stringify(shot.scrollTo)}));
        if (!heading) throw new Error("no heading matches ${shot.scrollTo}");
        const top = heading.getBoundingClientRect().top + window.scrollY -
          (document.querySelector("header")?.offsetHeight ?? 0) - 24;
        window.scrollTo({ top, behavior: "instant" });
      })()`);
      await sleep(400);
    }

    const { data } = await cdp.send("Page.captureScreenshot", { format: "png" }, sessionId);
    await writeFile(join(OUT, shot.file), Buffer.from(data, "base64"));
    console.log(`${shot.file} (${shot.role} @ ${shot.path})`);
  }

  ws.close();
} finally {
  const exited = new Promise((resolve) => chrome.once("exit", resolve));
  chrome.kill();
  await exited;
  await rm(profile, { recursive: true, force: true }).catch(() => {});
}
