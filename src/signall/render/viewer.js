// The document view of the Signall app: pdf.js's PDFViewer, plus clickable
// signature fields and drawing a new signature box.
//
// Host contract:
//   GET  doc.pdf        the document to show
//   GET  config.json    {xfa, fields: [{name, path, signed, signer, date, page, rect}]}
//                       xfa fields carry `path` (template names); others carry `page` and `rect` (PDF points)
//   message "signall"   {type: "ready", pages} | {type: "error", error}
//                       {type: "field", name}             a signature field was clicked
//                       {type: "box", page, rect}         a new box was drawn (page index, PDF points)
//                       {type: "collected", id, data}     reply to collect(): base64 PDF with form data, or null
//                       {type: "scale", value}            the zoom level changed
//   window.signall      setDrawMode(on), clearDraft(), collect(id), zoom(how), setDark(on)

import * as worker from "./pdfjs/build/pdf.worker.min.mjs";
globalThis.pdfjsWorker = worker; // run pdf.js in the main thread; no Worker needed

const pdfjs = await import("./pdfjs/build/pdf.min.mjs");
const { EventBus, PDFLinkService, PDFViewer } = await import("./pdfjs/web/pdf_viewer.mjs");

const post = (msg) => window.webkit.messageHandlers.signall.postMessage(JSON.stringify(msg));
const MIN_BOX = 12; // CSS pixels

let doc = null;
let viewer = null;
let config = { xfa: false, fields: [] };
let drawMode = false;
let draft = null;

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

function stamp(field) {
  const box = document.createElement("div");
  box.className = "signall-stamp";
  const who = document.createElement("b");
  who.textContent = `Digitally signed by ${field.signer || "unknown signer"}`;
  box.append(who);
  if (field.date) {
    const when = document.createElement("span");
    when.textContent = `Date: ${field.date}`;
    box.append(when);
  }
  return box;
}

function markXfaFields(pageDiv) {
  const candidates = [...pageDiv.querySelectorAll(".xfaLayer .xfaField")].filter(
    (el) => !el.querySelector("input, textarea, select"));
  for (const field of config.fields) {
    const el = candidates.find((c) => matchesPath(ancestorNames(c), field.path));
    if (!el || el.dataset.signallName) continue;
    el.dataset.signallName = field.name;
    if (field.signed) {
      el.classList.add("signall-xfa-signed");
      el.append(stamp(field));
    } else {
      el.classList.add("signall-xfa-field");
      el.title = "Sign here";
      el.addEventListener("click", () => post({ type: "field", name: field.name }));
    }
  }
}

function placeFields(pageView) {
  pageView.div.querySelectorAll(".signall-field").forEach((el) => el.remove());
  const index = pageView.id - 1;
  for (const field of config.fields) {
    if (field.signed || field.page !== index || !field.rect) continue;
    const [x0, y0, x1, y1] = pageView.viewport.convertToViewportRectangle(field.rect);
    const el = document.createElement("div");
    el.className = "signall-field";
    el.title = field.name;
    Object.assign(el.style, {
      left: `${Math.min(x0, x1)}px`, top: `${Math.min(y0, y1)}px`,
      width: `${Math.abs(x1 - x0)}px`, height: `${Math.abs(y1 - y0)}px`,
    });
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      post({ type: "field", name: field.name });
    });
    pageView.div.append(el);
  }
}

// --- Drawing a signature box -------------------------------------------------

function pageViewAt(target) {
  const pageDiv = target.closest?.(".page");
  if (!pageDiv) return null;
  return viewer.getPageView(Number(pageDiv.dataset.pageNumber) - 1);
}

function surface(pageView) {
  return pageView.div.querySelector(".canvasWrapper") || pageView.div;
}

function onPointerDown(e) {
  if (!drawMode || e.button !== 0) return;
  const pageView = pageViewAt(e.target);
  if (!pageView) return;
  e.preventDefault();
  clearDraft();
  const origin = surface(pageView).getBoundingClientRect();
  const el = document.createElement("div");
  el.className = "signall-draft";
  pageView.div.append(el);
  draft = { pageView, origin, x: e.clientX, y: e.clientY, el, done: false };
  pageView.div.setPointerCapture(e.pointerId);
  pageView.div.addEventListener("pointermove", onPointerMove);
  pageView.div.addEventListener("pointerup", onPointerUp, { once: true });
  onPointerMove(e);
}

function draftBox(e) {
  const { origin } = draft;
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const x0 = clamp(Math.min(draft.x, e.clientX), origin.left, origin.right) - origin.left;
  const x1 = clamp(Math.max(draft.x, e.clientX), origin.left, origin.right) - origin.left;
  const y0 = clamp(Math.min(draft.y, e.clientY), origin.top, origin.bottom) - origin.top;
  const y1 = clamp(Math.max(draft.y, e.clientY), origin.top, origin.bottom) - origin.top;
  return { x0, y0, x1, y1 };
}

function onPointerMove(e) {
  if (!draft || draft.done) return;
  const { x0, y0, x1, y1 } = draftBox(e);
  const offset = surface(draft.pageView).offsetLeft;
  const top = surface(draft.pageView).offsetTop;
  Object.assign(draft.el.style, {
    left: `${x0 + offset}px`, top: `${y0 + top}px`, width: `${x1 - x0}px`, height: `${y1 - y0}px`,
  });
}

function onPointerUp(e) {
  if (!draft) return;
  draft.pageView.div.removeEventListener("pointermove", onPointerMove);
  const { x0, y0, x1, y1 } = draftBox(e);
  if (x1 - x0 < MIN_BOX || y1 - y0 < MIN_BOX) {
    clearDraft();
    return;
  }
  draft.done = true;
  const vp = draft.pageView.viewport;
  const [ax, ay] = vp.convertToPdfPoint(x0, y1);
  const [bx, by] = vp.convertToPdfPoint(x1, y0);
  const rect = [Math.min(ax, bx), Math.min(ay, by), Math.max(ax, bx), Math.max(ay, by)].map(
    (v) => Math.round(v * 100) / 100);
  post({ type: "box", page: draft.pageView.id - 1, rect });
}

function clearDraft() {
  draft?.el.remove();
  draft = null;
}

// --- Host API ----------------------------------------------------------------

function toBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

window.signall = {
  setDrawMode(on) {
    drawMode = !!on;
    document.body.classList.toggle("signall-draw", drawMode);
    if (!drawMode) clearDraft();
  },
  clearDraft,
  async collect(id) {
    try {
      const data = doc.annotationStorage.size > 0 ? toBase64(await doc.saveDocument()) : null;
      post({ type: "collected", id, data });
    } catch (e) {
      post({ type: "collected", id, data: null, error: String(e) });
    }
  },
  zoom(how) {
    if (how === "in") viewer.updateScale({ steps: 1 });
    else if (how === "out") viewer.updateScale({ steps: -1 });
    else viewer.currentScaleValue = how; // "page-width", "page-fit", "1"
  },
  setDark(on) {
    document.documentElement.classList.toggle("dark", !!on);
  },
};

async function main() {
  config = await (await fetch("config.json")).json();
  window.signall.setDark(config.dark);
  const container = document.getElementById("viewerContainer");
  const eventBus = new EventBus();
  const linkService = new PDFLinkService({ eventBus });
  viewer = new PDFViewer({
    container, eventBus, linkService,
    annotationMode: config.forms ? pdfjs.AnnotationMode.ENABLE_FORMS : pdfjs.AnnotationMode.ENABLE,
  });
  linkService.setViewer(viewer);

  eventBus.on("pagesinit", () => { viewer.currentScaleValue = "page-width"; });
  eventBus.on("scalechanging", (e) => post({ type: "scale", value: e.scale }));
  eventBus.on("xfalayerrendered", (e) => markXfaFields(e.source.div));
  eventBus.on("pagerendered", (e) => { if (!config.xfa) placeFields(e.source); });

  container.addEventListener("pointerdown", onPointerDown);
  container.addEventListener("wheel", (e) => {
    if (!e.ctrlKey) return;
    e.preventDefault();
    viewer.updateScale({ steps: e.deltaY < 0 ? 1 : -1, origin: [e.clientX, e.clientY] });
  }, { passive: false });

  doc = await pdfjs.getDocument({
    url: "doc.pdf", enableXfa: config.xfa, standardFontDataUrl: "pdfjs/standard_fonts/",
  }).promise;
  viewer.setDocument(doc);
  linkService.setDocument(doc);
  await viewer.pagesPromise;
  post({ type: "ready", pages: doc.numPages, xfa: doc.isPureXfa });
}

main().catch((e) => post({ type: "error", error: String((e && e.stack) || e) }));
