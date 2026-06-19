/*
 * TrustGraphEngine — dependency-free, offline trust-graph renderer.
 *
 * No third-party libraries (no cytoscape / dagre / d3). Plain SVG + vanilla JS.
 * Shared by both /dashboard (wrapped in a React component) and the standalone
 * /trust-graph page so the two behave identically.
 *
 * Layout: layered left→right Sugiyama-style DAG (longest-path ranking +
 * barycenter crossing reduction). Deterministic — identical input renders
 * identically every refresh (no jitter on poll).
 *
 * Public API:
 *   const eng = new TrustGraphEngine(containerEl, {
 *     onSelectNode(d), onSelectEdge(d), onBackground(), onToggleGroup(id), onHover(d|null)
 *   });
 *   eng.update({ graphData, anomalies, hidden, expanded });  // diff-aware
 *   eng.fit();            // fit-to-view
 *   eng.focusLabel(label) // select + center a node by label or id
 *   eng.destroy();
 *
 * Static helpers exposed for hosts: TrustGraphEngine.GTYPE / .gcol / .gglyph
 */
(function (global) {
  "use strict";

  var SVGNS = "http://www.w3.org/2000/svg";

  var GTYPE = {
    agent:        { c: "#6366f1", g: "A", p: "Agents" },
    issuer:       { c: "#f59e0b", g: "I", p: "Issuers" },
    verifier:     { c: "#ef4444", g: "V", p: "Verifiers" },
    tool:         { c: "#10b981", g: "T", p: "Tools" },
    workload:     { c: "#3b82f6", g: "W", p: "Workloads" },
    mcp_server:   { c: "#ec4899", g: "M", p: "MCP Servers" },
    lifecycle_state: { c: "#94a3b8", g: "L", p: "Lifecycle" },
    tenant:       { c: "#8b5cf6", g: "O", p: "Tenants" },
    start:        { c: "#3aa9ff", g: "▶", p: "Start" },
    end:          { c: "#3aa9ff", g: "■", p: "End" },
    guardrail:    { c: "#34d399", g: "G", p: "Guardrails" },
    vulnerability:{ c: "#ef4444", g: "!", p: "Vulnerabilities" },
    policy:       { c: "#fb923c", g: "P", p: "Policies" },
  };
  function gcol(t) { return (GTYPE[t] || {}).c || "#6366f1"; }
  function gglyph(t) { return (GTYPE[t] || {}).g || "?"; }

  var COLLAPSE_MIN = 4;
  var COLLAPSIBLE = { verifier: 1, tool: 1, issuer: 1, lifecycle_state: 1 };

  function svgEl(tag, attrs) {
    var e = document.createElementNS(SVGNS, tag);
    if (attrs) { for (var k in attrs) { if (attrs[k] != null) e.setAttribute(k, attrs[k]); } }
    return e;
  }
  function clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }

  // Inject shared CSS once (scoped to .tge-* so it can't collide with host styles).
  function injectStyles() {
    if (document.getElementById("tge-styles")) return;
    var s = document.createElement("style");
    s.id = "tge-styles";
    s.textContent = [
      ".tge-root{position:relative;width:100%;height:100%;overflow:hidden;background:#070b12;border-radius:10px;}",
      ".tge-svg{width:100%;height:100%;display:block;cursor:grab;}",
      ".tge-svg.tge-panning{cursor:grabbing;}",
      ".tge-edge{fill:none;stroke:#33415588;stroke-width:1.1px;transition:stroke .12s,stroke-width .12s,opacity .12s;}",
      ".tge-edge.dim{opacity:.05;}",
      ".tge-edge.hot{stroke:#3b82f6;stroke-width:2px;opacity:1;}",
      ".tge-node{cursor:pointer;}",
      ".tge-node circle,.tge-node rect{transition:opacity .12s,stroke .12s;stroke:transparent;stroke-width:0;}",
      ".tge-node .tge-glyph{fill:#fff;font:700 9px ui-sans-serif,system-ui,sans-serif;text-anchor:middle;dominant-baseline:central;pointer-events:none;user-select:none;}",
      ".tge-node .tge-label{fill:#cbd5e1;font:600 9px ui-sans-serif,system-ui,sans-serif;text-anchor:middle;opacity:0;pointer-events:none;user-select:none;transition:opacity .12s;paint-order:stroke;stroke:#0b1220;stroke-width:3px;stroke-linejoin:round;}",
      ".tge-node.lbl .tge-label,.tge-node.group .tge-label{opacity:1;}",
      ".tge-node.dim{opacity:.12;}",
      ".tge-node.anom circle,.tge-node.anom rect{stroke:#f59e0b;stroke-width:3px;}",
      ".tge-node.sel circle,.tge-node.sel rect{stroke:#3b82f6;stroke-width:3.5px;}",
      ".tge-tooltip{position:absolute;z-index:30;pointer-events:none;background:#0b1220;border:1px solid #1e293b;border-radius:6px;padding:6px 9px;font:500 11px ui-sans-serif,system-ui,sans-serif;color:#e2e8f0;max-width:240px;box-shadow:0 4px 18px rgba(0,0,0,.5);opacity:0;transform:translateY(2px);transition:opacity .1s;}",
      ".tge-tooltip.show{opacity:1;transform:none;}",
      ".tge-tooltip .tt-type{text-transform:uppercase;font-weight:700;font-size:9px;}",
      ".tge-tooltip .tt-sub{color:#94a3b8;font-size:10px;margin-top:2px;}",
      ".tge-empty{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;color:#64748b;font:500 13px ui-sans-serif,system-ui,sans-serif;}",
      ".tge-empty .ico{font-size:30px;opacity:.6;}",
    ].join("");
    document.head.appendChild(s);
  }

  // ── clustering: collapse degree-1 leaves of COLLAPSIBLE types sharing a
  //    parent into an expandable group node (count badge). Mirrors the prior
  //    cytoscape buildElements so behaviour is unchanged.
  function buildElements(graphData, expanded, hidden, idx) {
    expanded = expanded || {}; hidden = hidden || {};
    var rawNodes = (graphData.nodes || []).filter(function (n) { return !hidden[n.node_type]; });
    var byId = {}; rawNodes.forEach(function (n) { byId[n.node_id] = n; });
    var rawEdges = (graphData.edges || []).filter(function (e) { return byId[e.src_node] && byId[e.dst_node]; });
    var incident = {}; rawNodes.forEach(function (n) { incident[n.node_id] = []; });
    rawEdges.forEach(function (e) { incident[e.src_node].push(e.dst_node); incident[e.dst_node].push(e.src_node); });
    var deg = {}; rawNodes.forEach(function (n) { deg[n.node_id] = incident[n.node_id].length; });

    var groups = {}, groupOfMember = {};
    rawNodes.forEach(function (n) {
      if (deg[n.node_id] === 1 && COLLAPSIBLE[n.node_type]) {
        var parent = incident[n.node_id][0], key = "grp:" + parent + ":" + n.node_type;
        (groups[key] = groups[key] || { parent: parent, type: n.node_type, members: [] }).members.push(n.node_id);
      }
    });
    var collapsed = {};
    Object.keys(groups).forEach(function (key) {
      var g = groups[key];
      g.members.forEach(function (m) { groupOfMember[m] = key; });
      if (g.members.length >= COLLAPSE_MIN && !expanded[key]) g.members.forEach(function (m) { collapsed[m] = key; });
    });

    var nodes = [], edges = [];
    rawNodes.forEach(function (n) {
      if (collapsed[n.node_id]) return;
      var an = idx.forNode(n);
      nodes.push({
        id: n.node_id, name: (n.label || "").replace(/^attest:/, ""), glyph: gglyph(n.node_type),
        ntype: n.node_type, degree: deg[n.node_id], r: 11 + Math.min(deg[n.node_id] * 1.1, 13),
        group: false, anom: an.length > 0,
      });
    });
    Object.keys(groups).forEach(function (key) {
      var g = groups[key];
      if (!(g.members.length >= COLLAPSE_MIN && !expanded[key])) return;
      var anyAnom = g.members.some(function (m) { return byId[m] && idx.forNode(byId[m]).length > 0; });
      var plural = (GTYPE[g.type] || {}).p || g.type;
      nodes.push({
        id: key, name: plural + " ×" + g.members.length, glyph: gglyph(g.type), ntype: g.type,
        group: true, count: g.members.length, r: 15 + Math.min(g.members.length * 0.5, 12), anom: anyAnom,
      });
      edges.push({ id: key + "|e", source: g.parent, target: key, etype: "attested_by", weight: g.members.length });
    });
    rawEdges.forEach(function (e, i) {
      if (collapsed[e.src_node] || collapsed[e.dst_node]) return;
      edges.push({
        id: "e" + i, source: e.src_node, target: e.dst_node, etype: e.edge_type,
        weight: e.weight || 1, srcLabel: e.src_label, dstLabel: e.dst_label,
      });
    });
    return { nodes: nodes, edges: edges, groupOfMember: groupOfMember };
  }

  // ── layered LR layout (longest-path rank + barycenter ordering) ─────────────
  var COL_SEP = 155, ROW_SEP = 40;
  function layout(nodes, edges) {
    if (!nodes.length) return;
    var byId = {}; nodes.forEach(function (n) { byId[n.id] = n; });
    var outAdj = {}, inAdj = {};
    nodes.forEach(function (n) { outAdj[n.id] = []; inAdj[n.id] = []; });
    edges.forEach(function (e) {
      if (byId[e.source] && byId[e.target] && e.source !== e.target) {
        outAdj[e.source].push(e.target); inAdj[e.target].push(e.source);
      }
    });
    // longest-path ranking (relaxation; capped to stay safe on cycles)
    var rank = {}; nodes.forEach(function (n) { rank[n.id] = 0; });
    var changed = true, iter = 0, cap = nodes.length + 5;
    while (changed && iter < cap) {
      changed = false; iter++;
      edges.forEach(function (e) {
        if (byId[e.source] && byId[e.target] && rank[e.target] < rank[e.source] + 1) {
          rank[e.target] = rank[e.source] + 1; changed = true;
        }
      });
    }
    // group into columns, deterministic initial order by id
    var cols = {};
    nodes.slice().sort(function (a, b) { return a.id < b.id ? -1 : a.id > b.id ? 1 : 0; })
      .forEach(function (n) { (cols[rank[n.id]] = cols[rank[n.id]] || []).push(n); });
    var rankKeys = Object.keys(cols).map(Number).sort(function (a, b) { return a - b; });
    var posOf = {};
    rankKeys.forEach(function (r) { cols[r].forEach(function (n, i) { posOf[n.id] = i; }); });
    // barycenter crossing reduction — alternating sweeps
    function bary(node, adj) {
      var nb = adj[node.id]; if (!nb.length) return posOf[node.id];
      var s = 0, c = 0; nb.forEach(function (m) { if (posOf[m] != null) { s += posOf[m]; c++; } });
      return c ? s / c : posOf[node.id];
    }
    for (var sweep = 0; sweep < 4; sweep++) {
      var asc = sweep % 2 === 0;
      var order = asc ? rankKeys : rankKeys.slice().reverse();
      order.forEach(function (r) {
        var adj = asc ? inAdj : outAdj;
        cols[r].sort(function (a, b) {
          var ba = bary(a, adj), bb = bary(b, adj);
          if (ba !== bb) return ba - bb;
          return a.id < b.id ? -1 : 1;
        });
        cols[r].forEach(function (n, i) { posOf[n.id] = i; });
      });
    }
    // assign coordinates. A rank with many siblings (e.g. a star/bipartite
    // population graph: 49 parallel agents) would otherwise be one very tall
    // column — a vertical line. Wrap any rank with > WRAP nodes into a grid of
    // ceil(sqrt(n)) sub-columns so it fills the canvas in 2D and stays legible.
    // Small ranks (pipelines) keep subCols=1 → clean single columns as before.
    var WRAP = 12, SUBCOL_SEP = 66;
    var dims = {};
    rankKeys.forEach(function (r) {
      var cnt = cols[r].length;
      var subCols = cnt > WRAP ? Math.ceil(Math.sqrt(cnt)) : 1;
      var rows = Math.ceil(cnt / subCols);
      dims[r] = { subCols: subCols, rows: rows, width: (subCols - 1) * SUBCOL_SEP, height: (rows - 1) * ROW_SEP };
    });
    var maxH = 0;
    rankKeys.forEach(function (r) { maxH = Math.max(maxH, dims[r].height); });
    var xCursor = 0;
    rankKeys.forEach(function (r) {
      var d = dims[r], col = cols[r];
      var y0 = (maxH - d.height) / 2;
      col.forEach(function (node, i) {
        var sc = i % d.subCols, sr = Math.floor(i / d.subCols);
        node.x = xCursor + sc * SUBCOL_SEP;
        node.y = y0 + sr * ROW_SEP;
      });
      xCursor += d.width + COL_SEP;
    });
  }

  function TrustGraphEngine(container, opts) {
    this.container = container;
    this.opts = opts || {};
    this.transform = { x: 0, y: 0, k: 1 };
    this.minZoom = 0.12; this.maxZoom = 3;
    this.sig = "";
    this.selectedId = null;
    this.nodeEls = {}; this.edgeEls = {};
    this.nodes = []; this.edges = [];
    this.outAdj = {}; this.inAdj = {};
    this.groupOfMember = {};
    this.pendingFocus = null;
    this.rawNodes = [];
    injectStyles();
    this._build();
  }

  TrustGraphEngine.GTYPE = GTYPE;
  TrustGraphEngine.gcol = gcol;
  TrustGraphEngine.gglyph = gglyph;
  TrustGraphEngine.COLLAPSE_MIN = COLLAPSE_MIN;
  TrustGraphEngine.buildElements = buildElements;

  TrustGraphEngine.prototype._build = function () {
    var self = this;
    this.container.classList.add("tge-root");
    this.container.innerHTML = "";
    var svg = svgEl("svg", { class: "tge-svg" });
    this.svg = svg;
    this.viewport = svgEl("g", { class: "tge-viewport" });
    this.edgeLayer = svgEl("g", {});
    this.nodeLayer = svgEl("g", {});
    this.viewport.appendChild(this.edgeLayer);
    this.viewport.appendChild(this.nodeLayer);
    svg.appendChild(this.viewport);
    this.container.appendChild(svg);
    this.tooltip = document.createElement("div");
    this.tooltip.className = "tge-tooltip";
    this.container.appendChild(this.tooltip);
    this.empty = document.createElement("div");
    this.empty.className = "tge-empty";
    this.empty.style.display = "none";
    this.empty.innerHTML = '<div class="ico">🕸</div><div>No graph data</div>';
    this.container.appendChild(this.empty);

    // wheel zoom toward cursor
    this._onWheel = function (e) {
      e.preventDefault();
      var rect = svg.getBoundingClientRect();
      var px = e.clientX - rect.left, py = e.clientY - rect.top;
      var t = self.transform;
      var factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
      var nk = clamp(t.k * factor, self.minZoom, self.maxZoom);
      t.x = px - (px - t.x) * (nk / t.k);
      t.y = py - (py - t.y) * (nk / t.k);
      t.k = nk;
      self._applyTransform();
    };
    svg.addEventListener("wheel", this._onWheel, { passive: false });

    // drag to pan (distinguish from click via movement threshold)
    this._panning = false; this._moved = false;
    this._onDown = function (e) {
      if (e.button !== 0) return;
      self._panning = true; self._moved = false;
      self._start = { x: e.clientX, y: e.clientY, tx: self.transform.x, ty: self.transform.y };
      svg.classList.add("tge-panning");
    };
    this._onMove = function (e) {
      if (!self._panning) return;
      var dx = e.clientX - self._start.x, dy = e.clientY - self._start.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) self._moved = true;
      self.transform.x = self._start.tx + dx;
      self.transform.y = self._start.ty + dy;
      self._applyTransform();
    };
    this._onUp = function () { self._panning = false; svg.classList.remove("tge-panning"); };
    svg.addEventListener("mousedown", this._onDown);
    window.addEventListener("mousemove", this._onMove);
    window.addEventListener("mouseup", this._onUp);

    // background click clears selection
    svg.addEventListener("click", function (e) {
      if (self._moved) return;
      if (e.target === svg || e.target === self.viewport) {
        self.selectedId = null; self._clearHighlight();
        if (self.opts.onBackground) self.opts.onBackground();
      }
    });
  };

  TrustGraphEngine.prototype._applyTransform = function () {
    var t = this.transform;
    this.viewport.setAttribute("transform", "translate(" + t.x + "," + t.y + ") scale(" + t.k + ")");
  };

  TrustGraphEngine.prototype.update = function (state) {
    state = state || {};
    var graphData = state.graphData || { nodes: [], edges: [] };
    var anomalies = state.anomalies || [];
    this.rawNodes = graphData.nodes || [];
    var idx = indexAnomalies(anomalies);
    var built = buildElements(graphData, state.expanded, state.hidden, idx);
    this.groupOfMember = built.groupOfMember;
    var sig = built.nodes.map(function (n) { return n.id; }).sort().join("|");

    var first = this.sig === "";
    if (sig !== this.sig) {
      this.sig = sig;
      this.nodes = built.nodes;
      this.edges = built.edges;
      this._render();
      if (first) this.fit();
      // honour a pending focus queued by a group-expand from focusLabel()
      if (this.pendingFocus) {
        var pid = this.pendingFocus; this.pendingFocus = null;
        if (this.nodeEls[pid]) { this._select(pid); this._centerOn(pid, Math.max(this.transform.k, 1.3)); }
      }
    } else {
      // topology unchanged (poll refresh) — only update anomaly halos, keep zoom/selection
      var byId = {}; built.nodes.forEach(function (n) { byId[n.id] = n; });
      this.nodes.forEach(function (n) {
        var nn = byId[n.id]; if (!nn) return;
        n.anom = nn.anom;
        var el = this.nodeEls[n.id];
        if (el) { if (n.anom) el.classList.add("anom"); else el.classList.remove("anom"); }
      }, this);
    }
  };

  TrustGraphEngine.prototype._render = function () {
    var self = this;
    layout(this.nodes, this.edges);
    this.edgeLayer.innerHTML = ""; this.nodeLayer.innerHTML = "";
    this.nodeEls = {}; this.edgeEls = {};
    var byId = {}; this.nodes.forEach(function (n) { byId[n.id] = n; });
    this.outAdj = {}; this.inAdj = {};
    this.nodes.forEach(function (n) { self.outAdj[n.id] = []; self.inAdj[n.id] = []; });

    this.empty.style.display = this.nodes.length ? "none" : "flex";

    // edges
    this.edges.forEach(function (e) {
      var s = byId[e.source], t = byId[e.target];
      if (!s || !t) return;
      self.outAdj[e.source].push(e.target); self.inAdj[e.target].push(e.source);
      var cx = (s.x + t.x) / 2;
      var d = "M" + s.x + " " + s.y + " C" + cx + " " + s.y + "," + cx + " " + t.y + "," + t.x + " " + t.y;
      var p = svgEl("path", { class: "tge-edge", d: d });
      p.__data = e;
      p.addEventListener("mouseenter", function (ev) { self._edgeHover(e, ev); });
      p.addEventListener("mouseleave", function () { self._hideTip(); if (!self.selectedId) self._clearHighlight(); });
      p.addEventListener("click", function (ev) {
        ev.stopPropagation();
        if (self._moved) return;
        self._highlightEdge(e);
        if (self.opts.onSelectEdge) self.opts.onSelectEdge(e);
      });
      self.edgeEls[e.id] = p;
      self.edgeLayer.appendChild(p);
    });

    // nodes
    this.nodes.forEach(function (n) {
      var g = svgEl("g", { class: "tge-node" + (n.anom ? " anom" : "") + (n.group ? " group" : ""), transform: "translate(" + n.x + "," + n.y + ")" });
      g.__data = n;
      var shape;
      if (n.group) {
        var w = n.r * 2.2, hh = n.r * 1.5;
        shape = svgEl("rect", { x: -w / 2, y: -hh / 2, width: w, height: hh, rx: 5, fill: gcol(n.ntype), "fill-opacity": 0.92 });
      } else {
        shape = svgEl("circle", { r: n.r, fill: gcol(n.ntype) });
      }
      g.appendChild(shape);
      var glyph = svgEl("text", { class: "tge-glyph", y: 0 });
      glyph.textContent = n.group ? n.glyph + "·" + n.count : n.glyph;
      g.appendChild(glyph);
      var label = svgEl("text", { class: "tge-label", y: n.r + 9 });
      label.textContent = n.name;
      g.appendChild(label);

      g.addEventListener("mouseenter", function () {
        g.classList.add("lbl");
        if (!self.selectedId) self._highlightHood(n.id, false);
        self._nodeHover(n);
      });
      g.addEventListener("mouseleave", function () {
        self._hideTip();
        if (!self.selectedId) { g.classList.remove("lbl"); self._clearHighlight(); }
        else self._applySelectedHighlight();
      });
      g.addEventListener("click", function (ev) {
        ev.stopPropagation();
        if (self._moved) return;
        if (n.group) { if (self.opts.onToggleGroup) self.opts.onToggleGroup(n.id); return; }
        self._select(n.id);
        if (self.opts.onSelectNode) self.opts.onSelectNode(n);
      });
      self.nodeEls[n.id] = g;
      self.nodeLayer.appendChild(g);
    });
  };

  // ── highlight helpers ───────────────────────────────────────────────────────
  TrustGraphEngine.prototype._clearHighlight = function () {
    for (var id in this.nodeEls) { this.nodeEls[id].classList.remove("dim", "lbl", "sel"); }
    for (var e in this.edgeEls) { this.edgeEls[e].classList.remove("dim", "hot"); }
  };
  TrustGraphEngine.prototype._highlightHood = function (id, persistent) {
    var hood = {}; hood[id] = 1;
    (this.outAdj[id] || []).forEach(function (m) { hood[m] = 1; });
    (this.inAdj[id] || []).forEach(function (m) { hood[m] = 1; });
    for (var nid in this.nodeEls) {
      var el = this.nodeEls[nid];
      if (hood[nid]) { el.classList.remove("dim"); el.classList.add("lbl"); }
      else { el.classList.add("dim"); el.classList.remove("lbl"); }
    }
    if (persistent && this.nodeEls[id]) this.nodeEls[id].classList.add("sel");
    for (var eid in this.edgeEls) {
      var ed = this.edgeEls[eid].__data;
      if (ed.source === id || ed.target === id) { this.edgeEls[eid].classList.add("hot"); this.edgeEls[eid].classList.remove("dim"); }
      else { this.edgeEls[eid].classList.add("dim"); this.edgeEls[eid].classList.remove("hot"); }
    }
  };
  TrustGraphEngine.prototype._applySelectedHighlight = function () {
    if (this.selectedId) this._highlightHood(this.selectedId, true);
  };
  TrustGraphEngine.prototype._select = function (id) {
    this.selectedId = id;
    this._highlightHood(id, true);
  };
  TrustGraphEngine.prototype._highlightEdge = function (e) {
    this.selectedId = null;
    for (var nid in this.nodeEls) {
      var el = this.nodeEls[nid];
      if (nid === e.source || nid === e.target) { el.classList.remove("dim"); el.classList.add("lbl"); }
      else { el.classList.add("dim"); el.classList.remove("lbl", "sel"); }
    }
    for (var eid in this.edgeEls) {
      if (eid === e.id) { this.edgeEls[eid].classList.add("hot"); this.edgeEls[eid].classList.remove("dim"); }
      else { this.edgeEls[eid].classList.add("dim"); this.edgeEls[eid].classList.remove("hot"); }
    }
  };

  // ── tooltips ─────────────────────────────────────────────────────────────────
  TrustGraphEngine.prototype._showTip = function (html, n) {
    this.tooltip.innerHTML = html;
    var rect = this.container.getBoundingClientRect();
    var sx = n.x * this.transform.k + this.transform.x;
    var sy = n.y * this.transform.k + this.transform.y;
    var tw = 200;
    this.tooltip.style.left = clamp(sx + 14, 4, rect.width - tw) + "px";
    this.tooltip.style.top = clamp(sy - 6, 4, rect.height - 40) + "px";
    this.tooltip.classList.add("show");
  };
  TrustGraphEngine.prototype._hideTip = function () { this.tooltip.classList.remove("show"); };
  TrustGraphEngine.prototype._nodeHover = function (n) {
    var sub = n.group ? (n.count + " collapsed — click to expand") : ("degree " + n.degree + " · click to inspect");
    this._showTip('<div class="tt-type" style="color:' + gcol(n.ntype) + '">' + esc(n.ntype) + '</div>' +
      esc(n.name) + '<div class="tt-sub">' + esc(sub) + '</div>', n);
    if (this.opts.onHover) this.opts.onHover(n);
  };
  TrustGraphEngine.prototype._edgeHover = function (e, ev) {
    var s = nodeById(this.nodes, e.source), t = nodeById(this.nodes, e.target);
    var anchor = { x: (s ? s.x : 0 + (t ? t.x : 0)) / 2, y: ((s ? s.y : 0) + (t ? t.y : 0)) / 2 };
    if (s && t) anchor = { x: (s.x + t.x) / 2, y: (s.y + t.y) / 2 };
    this._showTip('<div class="tt-type" style="color:#3b82f6">' + esc((e.etype || "edge").replace(/_/g, " ")) + '</div>' +
      '<div class="tt-sub">' + esc(e.srcLabel || e.source) + " → " + esc(e.dstLabel || e.target) + '</div>', anchor);
    // highlight endpoints on hover
    for (var nid in this.nodeEls) { if (!this.selectedId) this.nodeEls[nid].classList.add("dim"); }
    if (this.nodeEls[e.source]) this.nodeEls[e.source].classList.remove("dim");
    if (this.nodeEls[e.target]) this.nodeEls[e.target].classList.remove("dim");
  };

  // ── view controls ────────────────────────────────────────────────────────────
  TrustGraphEngine.prototype.fit = function () {
    if (!this.nodes.length) return;
    var minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    this.nodes.forEach(function (n) {
      minX = Math.min(minX, n.x - n.r); maxX = Math.max(maxX, n.x + n.r);
      minY = Math.min(minY, n.y - n.r); maxY = Math.max(maxY, n.y + n.r);
    });
    var rect = this.container.getBoundingClientRect();
    var pad = 50;
    var w = (maxX - minX) + pad * 2, hgt = (maxY - minY) + pad * 2;
    var k = clamp(Math.min(rect.width / w, rect.height / hgt), this.minZoom, 1.4);
    this.transform.k = k;
    this.transform.x = rect.width / 2 - ((minX + maxX) / 2) * k;
    this.transform.y = rect.height / 2 - ((minY + maxY) / 2) * k;
    this._applyTransform();
  };
  TrustGraphEngine.prototype._centerOn = function (id, zoom) {
    var n = nodeById(this.nodes, id); if (!n) return;
    var rect = this.container.getBoundingClientRect();
    var k = clamp(zoom || this.transform.k, this.minZoom, this.maxZoom);
    this._tweenTo(rect.width / 2 - n.x * k, rect.height / 2 - n.y * k, k);
  };
  TrustGraphEngine.prototype._tweenTo = function (tx, ty, tk) {
    var self = this, s = { x: this.transform.x, y: this.transform.y, k: this.transform.k };
    var steps = 14, i = 0;
    function step() {
      i++;
      var p = i / steps; p = 1 - Math.pow(1 - p, 3); // ease-out
      self.transform.x = s.x + (tx - s.x) * p;
      self.transform.y = s.y + (ty - s.y) * p;
      self.transform.k = s.k + (tk - s.k) * p;
      self._applyTransform();
      if (i < steps && global.requestAnimationFrame) global.requestAnimationFrame(step);
    }
    if (global.requestAnimationFrame) step(); else { this.transform = { x: tx, y: ty, k: tk }; this._applyTransform(); }
  };

  // ── focus by label / id (used by host panels, drill tables, anomaly view) ────
  TrustGraphEngine.prototype.focusLabel = function (label) {
    if (!label) return;
    var visible = this.nodes.find(function (n) { return !n.group && (n.name === label || n.id === label); });
    if (visible) {
      this._select(visible.id); this._centerOn(visible.id, Math.max(this.transform.k, 1.3));
      if (this.opts.onSelectNode) this.opts.onSelectNode(visible);
      return;
    }
    // not visible — may be inside a collapsed group; expand then center on update()
    var raw = (this.rawNodes || []).find(function (x) { return x.label === label || x.node_id === label; });
    if (raw && this.groupOfMember[raw.node_id]) {
      this.pendingFocus = raw.node_id;
      if (this.opts.onToggleGroup) this.opts.onToggleGroup(this.groupOfMember[raw.node_id]);
    }
  };

  TrustGraphEngine.prototype.destroy = function () {
    try {
      this.svg.removeEventListener("wheel", this._onWheel);
      this.svg.removeEventListener("mousedown", this._onDown);
      global.removeEventListener("mousemove", this._onMove);
      global.removeEventListener("mouseup", this._onUp);
    } catch (e) { /* noop */ }
    this.container.innerHTML = "";
  };

  // ── small utilities ───────────────────────────────────────────────────────────
  function nodeById(nodes, id) { for (var i = 0; i < nodes.length; i++) { if (nodes[i].id === id) return nodes[i]; } return null; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  // subject_node may be a node_id hash OR a label — index by both keys.
  function indexAnomalies(anoms) {
    var byKey = {};
    (anoms || []).forEach(function (a) { (byKey[a.subject_node] = byKey[a.subject_node] || []).push(a); });
    return {
      byKey: byKey,
      forNode: function (n) { return (byKey[n.node_id] || []).concat(byKey[n.label] || []); },
    };
  }
  TrustGraphEngine.indexAnomalies = indexAnomalies;

  global.TrustGraphEngine = TrustGraphEngine;
})(typeof window !== "undefined" ? window : this);
