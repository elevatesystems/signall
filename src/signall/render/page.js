// Lays out an XFA form with pdf.js, reports where its signature fields landed,
// and leaves the page ready to be printed to PDF by the host (WebKitGTK).
//
// Host contract:
//   GET  doc.pdf       the document to render
//   GET  fields.json   [{path: ["form1", "page1", ...], caption, font}] for signature fields
//   message "signall"  {ok, pages, fields: [{index, page, rect: [x0, y0, x1, y1]}]} or {ok: false, error}
//
// This follows pdf.js's own print path for XFA documents (getXfaHtmlForPrinting),
// which builds every page eagerly instead of only the ones visible on screen.

import * as worker from "./pdfjs/build/pdf.worker.min.mjs";
globalThis.pdfjsWorker = worker; // run pdf.js in the main thread; no Worker needed

const pdfjs = await import("./pdfjs/build/pdf.min.mjs");
const { SimpleLinkService } = await import("./pdfjs/web/pdf_viewer.mjs");

const post = (msg) => window.webkit.messageHandlers.signall.postMessage(JSON.stringify(msg));
const PX_TO_PT = 72 / 96;
const CSS_SCALE = 96 / 72;

function ancestorNames(el) {
  const names = [];
  for (let n = el; n && n.getAttribute; n = n.parentElement) {
    const name = n.getAttribute("xfaname");
    if (name) names.unshift(name);
  }
  return names;
}

// True if `want` appears in `have` as an ordered subsequence and both end with the same name.
function matchesPath(have, want) {
  if (have[have.length - 1] !== want[want.length - 1]) return false;
  let i = 0;
  for (const name of have) if (i < want.length && name === want[i]) i++;
  return i === want.length;
}

async function main() {
  const fields = await (await fetch("fields.json")).json();
  const doc = await pdfjs.getDocument({
    url: "doc.pdf", enableXfa: true, standardFontDataUrl: "pdfjs/standard_fonts/",
  }).promise;
  if (!doc.isPureXfa) throw new Error("document is not a dynamic XFA form");

  const root = document.getElementById("pages");
  const linkService = new SimpleLinkService();
  const pages = [];
  for (const xfaPage of doc.allXfaHtml.children) {
    const viewport = pdfjs.getXfaPageViewport(xfaPage, { scale: CSS_SCALE });
    const page = document.createElement("div");
    page.className = "signall-page";
    page.style.width = `${viewport.width}px`;
    page.style.height = `${viewport.height}px`;
    const layer = document.createElement("div");
    layer.className = "xfaLayer";
    page.append(layer);
    root.append(page);
    pdfjs.XfaLayer.render({
      viewport: viewport.clone({ dontFlip: true }), div: layer, xfaHtml: xfaPage,
      annotationStorage: doc.annotationStorage, linkService, intent: "print",
    });
    pages.push(page);
  }
  await document.fonts.ready;

  const candidates = [...document.querySelectorAll(".xfaLayer .xfaField")].filter(
    (el) => !el.querySelector("input, textarea, select"));
  const results = [];
  fields.forEach((field, index) => {
    const el = candidates.find((c) => matchesPath(ancestorNames(c), field.path));
    if (!el) return;
    const pageEl = el.closest(".signall-page");
    const p = pageEl.getBoundingClientRect();
    const r = el.getBoundingClientRect();
    const heightPt = p.height * PX_TO_PT;
    results.push({
      index, page: pages.indexOf(pageEl),
      rect: [
        (r.left - p.left) * PX_TO_PT, heightPt - (r.bottom - p.top) * PX_TO_PT,
        (r.right - p.left) * PX_TO_PT, heightPt - (r.top - p.top) * PX_TO_PT,
      ],
    });
    // pdf.js drops signature-field captions; draw them so the printed form matches Acrobat.
    if (field.caption) {
      const cap = document.createElement("div");
      cap.className = "signall-caption";
      cap.textContent = field.caption;
      cap.style.font = field.font || "bold 8pt sans-serif";
      el.appendChild(cap);
    }
  });
  post({ ok: true, pages: pages.length, fields: results, candidates: candidates.length });
}

main().catch((e) => post({ ok: false, error: String((e && e.stack) || e) }));
