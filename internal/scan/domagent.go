package scan

import (
	"encoding/json"
	"strings"
)

// domCanary is one unique marker injected into a single source, carrying the
// stable probe identity that a sink hit is attributed to. The Token is the
// random, non-executing marker used only for correlation; ID is the stable
// probe identity (kind:name) that appears in findings.
type domCanary struct {
	ID           string   `json:"id"`
	Token        string   `json:"token"`
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	DiscoveredBy []string `json:"discoveredBy,omitempty"`
	// Value is the string actually injected into the source. It defaults to Token
	// when empty. Confirm-mode payloads set Value to an executing payload that
	// still embeds Token, so a sink hit is attributed by matching Token while the
	// payload's execution triggers the hidden confirmation beacon.
	Value string `json:"value,omitempty"`
}

// domAgentLimits bounds the agent's in-page state so a hostile or busy page
// cannot make the collected evidence grow without limit.
type domAgentLimits struct {
	MaxFindings int `json:"maxFindings"`
	PreviewMax  int `json:"previewMax"`
	StackDepth  int `json:"stackDepth"`
}

// domAgentConfig is the JSON the injected agent reads to know its mode, the
// canaries to correlate, and its resource bounds.
type domAgentConfig struct {
	Mode     string          `json:"mode"`
	Token    string          `json:"token"` // relay/report secret, filters our own messages
	Canaries []domCanary     `json:"canaries"`
	Limits   domAgentLimits  `json:"limits"`
	Messages bool            `json:"messages"`
	Sinks    map[string]bool `json:"sinks"` // nil = all sink families enabled
}

// domRawFrame mirrors DOMStackFrame for decoding the agent's captured stacks.
type domRawFrame struct {
	Function string `json:"function"`
	URL      string `json:"url"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// domRawMessage carries the agent's postMessage evidence.
type domRawMessage struct {
	ListenerCount          int           `json:"listenerCount"`
	OriginChecked          bool          `json:"originChecked"`
	OriginCheckedListeners int           `json:"originCheckedListeners"`
	SourceChecked          bool          `json:"sourceChecked"`
	SourceCheckedListeners int           `json:"sourceCheckedListeners"`
	DataShape              string        `json:"dataShape"`
	ReachesSink            bool          `json:"reachesSink"`
	ProbeGenerated         bool          `json:"probeGenerated"`
	SentToOrigin           string        `json:"sentToOrigin"`
	Identity               string        `json:"identity"`
	ListenerLocations      []domRawFrame `json:"listenerLocations"`
}

// domRawURL mirrors the structural URL evidence produced in-page.
type domRawURL struct {
	Resolved          bool   `json:"resolved"`
	Scheme            string `json:"scheme"`
	DestinationOrigin string `json:"destinationOrigin"`
	SameOrigin        bool   `json:"sameOrigin"`
	CanaryComponent   string `json:"canaryComponent"`
	InputKind         string `json:"inputKind"`
	ExecutableScheme  bool   `json:"executableScheme"`
}

// domRawFinding is one record the in-page agent produced, decoded on the Go
// side and mapped into a DOMFinding with severity, confidence and target filled
// in.
type domRawFinding struct {
	Kind       string         `json:"kind"` // flow | sink | message
	Sink       string         `json:"sink"`
	Argument   int            `json:"argument"`
	Context    string         `json:"context"`
	Value      string         `json:"value"`
	ProbeID    string         `json:"probeId"`
	SourceKind string         `json:"sourceKind"`
	SourceName string         `json:"sourceName"`
	Discovered []string       `json:"discoveredBy"`
	Transform  string         `json:"transform"`
	Stack      []domRawFrame  `json:"stack"`
	FrameURL   string         `json:"frameUrl"`
	FramePath  string         `json:"framePath"`
	Message    *domRawMessage `json:"message"`
	URL        *domRawURL     `json:"url"`
}

// domAgentState is the whole in-page agent state Go reads back after a load or
// interaction: the findings, which probe ids confirmed execution, and a count
// of exceptions the hooks swallowed (used to flag pages whose execution the
// instrumentation may have disturbed).
type domAgentState struct {
	Findings      []domRawFinding `json:"findings"`
	Confirmations map[string]bool `json:"confirmations"`
	HookErrors    int             `json:"hookErrors"`
}

// buildDOMAgent returns the instrumentation script with its configuration
// inlined, ready to install via Page.addScriptToEvaluateOnNewDocument so it runs
// in every frame before the page's own scripts.
func buildDOMAgent(cfg domAgentConfig) string {
	data, err := json.Marshal(cfg)
	if err != nil {
		// cfg contains only strings, bools and ints, so marshalling cannot fail;
		// fall back to a null config that leaves the agent inert rather than panic.
		data = []byte("null")
	}
	return strings.Replace(domAgentScript, "__JSMDOM_CONFIG__", string(data), 1)
}

// domAgentScript is the DOM-instrumentation agent. It is injected before page
// scripts run, in every frame, and:
//
//   - seeds attacker-controllable sources it can set from JS (window.name,
//     localStorage, sessionStorage, cookies) with their canary markers;
//   - wraps security-sensitive sinks (HTML injection, JS execution, navigation,
//     script-URL and event-handler-attribute sinks), recording each call with a
//     bounded value preview and a captured, bounded call stack;
//   - correlates the recorded value against the known canaries so a sink hit is
//     attributed to the exact source that controlled it (a flow), rather than
//     merely noting that a dangerous API ran;
//   - analyses postMessage: listeners (and whether they appear to inspect
//     origin/source), observed messages, and cross-origin sends of URL-derived
//     data;
//   - relays findings from cross-origin child frames up to the top frame so a
//     single read collects every frame's evidence.
//
// Every hook calls the original API and returns its result, so the page keeps
// working; every step is wrapped in try/catch so a hook can never throw into
// page code. It is idempotent (guarded by __jsmdomInstalled).
const domAgentScript = `
(function() {
  "use strict";
  var CONFIG = __JSMDOM_CONFIG__;
  if (!CONFIG) return;

  // Idempotent install: the agent is injected on every new document, but a page
  // that re-runs it (or a same-document re-eval) must not double-wrap.
  if (window.__jsmdomInstalled) return;
  window.__jsmdomInstalled = true;

  var MODE = CONFIG.mode || 'canary';
  var CANARIES = CONFIG.canaries || [];
  var TOKEN = CONFIG.token || '';
  var LIM = CONFIG.limits || { maxFindings: 300, previewMax: 120, stackDepth: 8 };
  var MAXF = LIM.maxFindings || 300;
  var PREVIEW = LIM.previewMax || 120;
  var STACKD = LIM.stackDepth || 8;
  var SINKS = CONFIG.sinks || null; // null => all enabled

  var agent = window.__jsmdom = window.__jsmdom || {
    findings: [], confirmations: {}, hookErrors: 0, seenMessages: {}
  };
  var NATIVE_ADD = window.addEventListener;
  var NATIVE_SET_TIMEOUT = window.setTimeout;
  agent.lastActivity = performance.now();
  (function watchDOMActivity() {
    function start() {
      try {
        if (!document.documentElement || agent.activityObserver) return;
        agent.activityObserver = new MutationObserver(function () { agent.lastActivity = performance.now(); });
        agent.activityObserver.observe(document.documentElement, {
          childList: true, subtree: true, attributes: true, characterData: true
        });
      } catch (e) {}
    }
    if (document.readyState === 'loading') NATIVE_ADD.call(document, 'DOMContentLoaded', start, { once: true });
    else start();
  })();

  function sinkEnabled(family) {
    if (!SINKS) return true;
    return !!SINKS[family];
  }
  function noteErr() { try { agent.hookErrors++; } catch (e) {} }

  // ---- value coercion & preview -------------------------------------------
  function toStr(v) {
    try {
      if (v === null || v === undefined) return '';
      if (typeof v === 'string') return v.length > 8192 ? v.slice(0, 8192) : v;
      if (typeof v === 'object') {
        if (v.nodeType && v.outerHTML) return String(v.outerHTML).slice(0, 8192);
        try { return JSON.stringify(v).slice(0, 8192); } catch (e) { return String(v).slice(0, 8192); }
      }
      return String(v).slice(0, 8192);
    } catch (e) { return ''; }
  }
  function preview(value, token) {
    var s = value;
    if (token) {
      var idx = s.indexOf(token);
      if (idx >= 0) {
        var start = Math.max(0, idx - 30);
        s = (start > 0 ? '…' : '') + s.slice(start, idx + token.length + 30);
      }
    }
    if (s.length > PREVIEW) s = s.slice(0, PREVIEW) + '…';
    // Never let our own relay token leak into a preview.
    if (TOKEN) s = s.split(TOKEN).join('');
    return s;
  }

  // Return structural URL evidence without retaining the full destination.
  // This lets the Go side distinguish ordinary same-origin query propagation
  // from cross-origin or executable-scheme navigation.
  function analyseURL(value, token) {
    var out = {
      resolved: false, scheme: '', destinationOrigin: '', sameOrigin: false,
      canaryComponent: '', inputKind: '', executableScheme: false
    };
    try {
      var trimmed = (value || '').trim();
      if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(trimmed)) out.inputKind = 'absolute';
      else if (trimmed.indexOf('//') === 0) out.inputKind = 'protocol_relative';
      else if (trimmed.indexOf('/') === 0) out.inputKind = 'root_relative';
      else if (trimmed.indexOf('?') === 0) out.inputKind = 'query_relative';
      else if (trimmed.indexOf('#') === 0) out.inputKind = 'fragment_relative';
      else out.inputKind = 'path_relative';

      var u = new URL(trimmed, location.href);
      out.resolved = true;
      out.scheme = (u.protocol || '').replace(/:$/, '').toLowerCase();
      out.executableScheme = out.scheme === 'javascript' || out.scheme === 'vbscript' ||
        (out.scheme === 'data' && /^data\s*:\s*text\/(?:html|javascript)/i.test(trimmed));
      if (u.origin && u.origin !== 'null') out.destinationOrigin = u.origin;
      out.sameOrigin = !!out.destinationOrigin && out.destinationOrigin === location.origin;

      function has(part) {
        if (!part || !token) return false;
        if (part.indexOf(token) !== -1) return true;
        try { return decodeURIComponent(part).indexOf(token) !== -1; } catch (e) { return false; }
      }
      if (has(u.protocol)) out.canaryComponent = 'scheme';
      else if (has(u.username) || has(u.password)) out.canaryComponent = 'credentials';
      else if (has(u.hostname) || has(u.port)) out.canaryComponent = 'authority';
      else if (has(u.pathname)) out.canaryComponent = 'path';
      else if (has(u.search)) out.canaryComponent = 'query';
      else if (has(u.hash)) out.canaryComponent = 'fragment';
      else if (has(trimmed)) out.canaryComponent = 'opaque';
    } catch (e) {}
    return out;
  }

  // ---- canary correlation --------------------------------------------------
  function matchCanaries(value) {
    var out = [];
    if (!value) return out;
    var decoded = value;
    // Every marker carries this fixed alphanumeric prefix. Almost every sink a
    // normal application calls is unrelated to our probes, so reject those
    // values before URL decoding and before walking as many as 100 canaries.
    if (value.indexOf('jsmdom') === -1) {
      if (value.indexOf('%') === -1) return out;
      try { decoded = decodeURIComponent(value); } catch (e) {}
      if (decoded.indexOf('jsmdom') === -1) return out;
    } else {
      try { decoded = decodeURIComponent(value); } catch (e) {}
    }
    for (var i = 0; i < CANARIES.length; i++) {
      var c = CANARIES[i];
      if (!c || !c.token) continue;
      if (value.indexOf(c.token) !== -1) {
        out.push({ id: c.id, kind: c.kind, name: c.name, token: c.token, transform: '', discoveredBy: c.discoveredBy || [] });
      } else if (decoded !== value && decoded.indexOf(c.token) !== -1) {
        out.push({ id: c.id, kind: c.kind, name: c.name, token: c.token, transform: 'url_decoded', discoveredBy: c.discoveredBy || [] });
      }
    }
    return out;
  }

  // ---- stack capture -------------------------------------------------------
  function parseFrame(line) {
    line = (line || '').trim();
    if (line.indexOf('at ') === 0) line = line.slice(3);
    var fn = '';
    var loc = line;
    var m = line.match(/^(.*?)\s+\((.*)\)$/);
    if (m) { fn = m[1]; loc = m[2]; }
    var lm = loc.match(/^(.*):(\d+):(\d+)$/);
    if (!lm) return null;
    return { function: fn, url: lm[1], line: parseInt(lm[2], 10) || 0, column: parseInt(lm[3], 10) || 0 };
  }
  function captureStack() {
    var frames = [];
    try {
      var raw = (new Error()).stack || '';
      var lines = raw.split('\n');
      for (var i = 0; i < lines.length && frames.length < STACKD; i++) {
        var f = parseFrame(lines[i]);
        if (!f) continue;
        // Keep only real page/script frames. Our injected agent's own frames
        // surface with a non-http pseudo URL (or none) and the sink wrappers are
        // anonymous, so requiring an http(s) URL drops them and leaves the page
        // code that actually drove data into the sink.
        if (!f.url || f.url.indexOf('http') !== 0) continue;
        frames.push(f);
      }
    } catch (e) { noteErr(); }
    return frames;
  }

  // ---- cross-frame plumbing ------------------------------------------------
  function topAgent() {
    try { if (window.top === window) return agent; } catch (e) {}
    try { if (window.top.__jsmdom) return window.top.__jsmdom; } catch (e) {}
    return null; // cross-origin parent: unreadable, relay instead
  }
  function framePath() {
    try { if (window.top === window) return 'main'; } catch (e) { return 'frame'; }
    try {
      var idx = [], w = window;
      while (w !== w.top) {
        var sib = w.parent.frames, found = -1;
        for (var i = 0; i < sib.length; i++) { if (sib[i] === w) { found = i; break; } }
        idx.unshift(found);
        w = w.parent;
      }
      return 'main/' + idx.map(function (i) { return 'frame[' + i + ']'; }).join('/');
    } catch (e) { return 'frame'; }
  }
  function emit(obj) {
    obj.frameUrl = location.href;
    obj.framePath = framePath();
    var t = topAgent();
    if (t) {
      if (t.findings.length < MAXF) t.findings.push(obj);
    } else {
      try { window.top.postMessage({ __jsmdom_relay: TOKEN, finding: obj }, '*'); } catch (e) {}
    }
  }

  // ---- the shared sink recorder -------------------------------------------
  function __jsmdomRecord(sink, arg, rawValue, ctx) {
    try {
      var value = toStr(rawValue);
      var matched = matchCanaries(value);
      if (matched.length) {
        var stack = captureStack();
        for (var i = 0; i < matched.length; i++) {
          var mc = matched[i];
          emit({
            kind: 'flow', sink: sink, argument: arg, context: ctx,
            value: preview(value, mc.token), probeId: mc.id,
            sourceKind: mc.kind, sourceName: mc.name, discoveredBy: mc.discoveredBy,
            transform: mc.transform,
            stack: stack, url: ctx === 'url' ? analyseURL(value, mc.token) : null
          });

          // The capture-phase message observer records the active message just
          // before application listeners run. Correlate a web-message flow back
          // to that observation so reachesSink becomes real evidence rather than
          // a permanently-false placeholder.
          if (mc.kind === 'web_message' && agent.activeMessage) {
            try {
              var am = agent.activeMessage;
              am.message.reachesSink = true;
              emit({ kind: 'message', message: {
                listenerCount: am.message.listenerCount,
                originChecked: am.message.originChecked,
                originCheckedListeners: am.message.originCheckedListeners,
                sourceChecked: am.message.sourceChecked,
                sourceCheckedListeners: am.message.sourceCheckedListeners,
                dataShape: am.message.dataShape, identity: am.message.identity,
                reachesSink: true, probeGenerated: am.message.probeGenerated,
                sentToOrigin: '', listenerLocations: am.message.listenerLocations
              }});
            } catch (e) { noteErr(); }
          }
        }
      } else if (MODE === 'observe' && value) {
        var stack = captureStack();
        emit({ kind: 'sink', sink: sink, argument: arg, context: ctx,
               value: preview(value, null), stack: stack });
      }
    } catch (e) { noteErr(); }
  }
  // Register a canary discovered after the initial navigation (a form input, a
  // web message) so it is correlated without a state-losing reload.
  window.__jsmdomAddCanary = function (c) {
    try { if (c && c.token) CANARIES.push(c); } catch (e) { noteErr(); }
  };
  // Exposed for the confirm-mode payloads (a hidden execution beacon; never a
  // visible dialog).
  window.__jsmdomConfirm = function (pid) {
    try {
      var t = topAgent();
      if (t) { t.confirmations[pid] = true; }
      else { window.top.postMessage({ __jsmdom_relay: TOKEN, confirm: pid }, '*'); }
    } catch (e) { noteErr(); }
    return 1;
  };

  // ---- hook installers -----------------------------------------------------
  function hookProp(proto, prop, sinkName, ctx, family) {
    if (!sinkEnabled(family)) return;
    try {
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set || d.set.__jsmdom) return;
      var origSet = d.set, origGet = d.get;
      var newSet = function (v) { __jsmdomRecord(sinkName, 0, v, ctx); return origSet.call(this, v); };
      newSet.__jsmdom = true;
      Object.defineProperty(proto, prop, { configurable: true, enumerable: d.enumerable, get: origGet, set: newSet });
    } catch (e) { noteErr(); }
  }
  function hookMethod(obj, name, sinkName, ctx, argIdx, family) {
    if (!sinkEnabled(family)) return;
    try {
      var orig = obj[name];
      if (typeof orig !== 'function' || orig.__jsmdom) return;
      var wrap = function () { __jsmdomRecord(sinkName, argIdx, arguments[argIdx], ctx); return orig.apply(this, arguments); };
      wrap.__jsmdom = true;
      try { wrap.prototype = orig.prototype; } catch (e) {}
      obj[name] = wrap;
    } catch (e) { noteErr(); }
  }

  // HTML sinks
  hookProp(Element.prototype, 'innerHTML', 'Element.innerHTML', 'html', 'innerHTML');
  hookProp(Element.prototype, 'outerHTML', 'Element.outerHTML', 'html', 'outerHTML');
  hookMethod(Element.prototype, 'insertAdjacentHTML', 'Element.insertAdjacentHTML', 'html', 1, 'insertAdjacentHTML');
  hookMethod(document, 'write', 'document.write', 'html', 0, 'document.write');
  hookMethod(document, 'writeln', 'document.writeln', 'html', 0, 'document.write');
  try { hookProp(HTMLIFrameElement.prototype, 'srcdoc', 'HTMLIFrameElement.srcdoc', 'html', 'srcdoc'); } catch (e) {}

  // JS execution sinks
  hookMethod(window, 'eval', 'eval', 'js', 0, 'eval');
  (function () {
    if (!sinkEnabled('Function')) return;
    try {
      var OF = window.Function;
      if (OF.__jsmdom) return;
      var FW = function () {
        try {
          var n = arguments.length ? arguments.length - 1 : 0;
          __jsmdomRecord('Function', n, arguments[n], 'js');
        } catch (e) { noteErr(); }
        return OF.apply(this, Array.prototype.slice.call(arguments));
      };
      FW.prototype = OF.prototype;
      FW.__jsmdom = true;
      window.Function = FW;
    } catch (e) { noteErr(); }
  })();
  (function () {
    ['setTimeout', 'setInterval'].forEach(function (name) {
      var fam = 'setTimeout';
      if (!sinkEnabled(fam)) return;
      try {
        var orig = window[name];
        if (typeof orig !== 'function' || orig.__jsmdom) return;
        var wrap = function (fn) {
          try { if (typeof fn === 'string') __jsmdomRecord(name, 0, fn, 'js'); } catch (e) { noteErr(); }
          return orig.apply(this, arguments);
        };
        wrap.__jsmdom = true;
        window[name] = wrap;
      } catch (e) { noteErr(); }
    });
  })();

  // Script-URL sink
  try { hookProp(HTMLScriptElement.prototype, 'src', 'HTMLScriptElement.src', 'url', 'script.src'); } catch (e) {}

  // Navigation sinks
  hookMethod(window, 'open', 'window.open', 'url', 0, 'navigation');
  try { hookMethod(Location.prototype, 'assign', 'location.assign', 'url', 0, 'navigation'); } catch (e) {}
  try { hookMethod(Location.prototype, 'replace', 'location.replace', 'url', 0, 'navigation'); } catch (e) {}
  try { hookProp(HTMLAnchorElement.prototype, 'href', 'HTMLAnchorElement.href', 'url', 'navigation'); } catch (e) {}
  try { hookProp(HTMLIFrameElement.prototype, 'src', 'HTMLIFrameElement.src', 'url', 'navigation'); } catch (e) {}
  try { hookProp(HTMLFormElement.prototype, 'action', 'HTMLFormElement.action', 'url', 'navigation'); } catch (e) {}

  // Generic setAttribute: event-handler attributes, srcdoc, and src/href/action.
  (function () {
    try {
      var orig = Element.prototype.setAttribute;
      if (orig.__jsmdom) return;
      var wrap = function (name, value) {
        try {
          var n = ('' + name).toLowerCase();
          if (n.indexOf('on') === 0 && sinkEnabled('event-handler')) {
            __jsmdomRecord('Element.setAttribute(' + n + ')', 1, value, 'attribute');
          } else if (n === 'srcdoc' && sinkEnabled('srcdoc')) {
            __jsmdomRecord('Element.setAttribute(srcdoc)', 1, value, 'html');
          } else if ((n === 'src' || n === 'href' || n === 'action')) {
            var tag = (this.tagName || '').toLowerCase();
            var fam = (tag === 'script') ? 'script.src' : 'navigation';
            if (sinkEnabled(fam)) __jsmdomRecord('Element.setAttribute(' + n + ')', 1, value, 'url');
          }
        } catch (e) { noteErr(); }
        return orig.apply(this, arguments);
      };
      wrap.__jsmdom = true;
      Element.prototype.setAttribute = wrap;
    } catch (e) { noteErr(); }
  })();

  // ---- postMessage analysis ------------------------------------------------
  if (CONFIG.messages) {
    // Detect message listeners and whether they inspect origin/source.
    try {
      var origAdd = window.addEventListener;
      if (!origAdd.__jsmdom) {
        var wrapAdd = function (type, listener, opts) {
          try {
            if (type === 'message' && typeof listener === 'function') recordListener(listener);
          } catch (e) { noteErr(); }
          return origAdd.apply(this, arguments);
        };
        wrapAdd.__jsmdom = true;
        window.addEventListener = wrapAdd;
      }
    } catch (e) { noteErr(); }

    function recordListener(fn) {
      var src = '';
      try { src = fn.toString(); } catch (e) {}
      // Evidence of inspection only — not proof of correct validation.
      var originChecked = /\.origin\b/.test(src) || /\borigin\s*[=!]==?/.test(src);
      var sourceChecked = /\.source\b/.test(src);
      var shape = extractShape(src);
      var stack = captureStack();
      var t = topAgent() || agent;
      try {
        t.__msgListeners = t.__msgListeners || [];
        t.__msgListeners.push({
          originChecked: originChecked, sourceChecked: sourceChecked, shape: shape,
          location: stack.length ? stack[0] : null
        });
      } catch (e) {}
    }
    function extractShape(src) {
      try {
        var props = {}, re = /(?:event|e|msg|ev|m)\.data\.([A-Za-z_$][\w$]*)/g, m;
        while ((m = re.exec(src)) !== null) props[m[1]] = true;
        var keys = Object.keys(props);
        if (!keys.length) return '';
        return '{' + keys.slice(0, 8).join(', ') + '}';
      } catch (e) { return ''; }
    }

    // Observe incoming messages (capture phase, via the native add so our own
    // wrapper does not re-log it). Our relay messages are filtered out.
    try {
      NATIVE_ADD.call(window, 'message', function (ev) {
        try {
          if (ev && ev.data && ev.data.__jsmdom_relay) return;
          recordMessage(ev);
        } catch (e) { noteErr(); }
      }, true);
    } catch (e) { noteErr(); }

    function recordMessage(ev) {
      var origin = '';
      try { origin = ev.origin || ''; } catch (e) {}
      var shape = '';
      try {
        if (ev.data && typeof ev.data === 'object') shape = '{' + Object.keys(ev.data).slice(0, 8).join(', ') + '}';
        else shape = typeof ev.data;
      } catch (e) {}
      var identity = origin + '|' + shape;
      var t = topAgent() || agent;
      var listeners = (t.__msgListeners || []);
      var originChecked = false, sourceChecked = false, dataShape = '';
      var originCheckedListeners = 0, sourceCheckedListeners = 0, listenerLocations = [];
      for (var i = 0; i < listeners.length; i++) {
        if (listeners[i].originChecked) { originChecked = true; originCheckedListeners++; }
        if (listeners[i].sourceChecked) { sourceChecked = true; sourceCheckedListeners++; }
        if (!dataShape && listeners[i].shape) dataShape = listeners[i].shape;
        if (listeners[i].location && listenerLocations.length < 8) listenerLocations.push(listeners[i].location);
      }
      var probeGenerated = matchCanaries(toStr(ev.data)).length > 0;
      var finding = {
        kind: 'message',
        message: {
          listenerCount: listeners.length,
          originChecked: originChecked, sourceChecked: sourceChecked,
          originCheckedListeners: originCheckedListeners,
          sourceCheckedListeners: sourceCheckedListeners,
          dataShape: dataShape || shape, identity: identity, reachesSink: false,
          probeGenerated: probeGenerated, sentToOrigin: '', listenerLocations: listenerLocations
        }
      };
      agent.activeMessage = finding;
      // Keep the correlation through listener-created promise microtasks, then
      // clear it before unrelated later activity can be misattributed.
      try {
        NATIVE_SET_TIMEOUT.call(window, function () {
          if (agent.activeMessage === finding) agent.activeMessage = null;
        }, 0);
      } catch (e) {}
      if (!agent.seenMessages[identity]) {
        agent.seenMessages[identity] = true; // duplicates are grouped by stable identity
        emit(finding);
      }
    }

    // Detect cross-origin sends of URL-derived data.
    (function () {
      try {
        var WP = Window.prototype, origPost = WP.postMessage;
        if (typeof origPost !== 'function' || origPost.__jsmdom) return;
        var wrap = function (message, targetOrigin) {
          try {
            var to = (targetOrigin === undefined || targetOrigin === null) ? '' : String(targetOrigin);
            var str = toStr(message);
            var carries = matchCanaries(str).length > 0 || (location.host && str.indexOf(location.host) !== -1);
            var crossOrigin = to === '*' || (to && to.indexOf('/') !== -1 && to.indexOf(location.origin) !== 0);
            if (carries && crossOrigin && !agent.sendingProbe) {
              emit({ kind: 'message',
                     message: { sentToOrigin: to, reachesSink: false, listenerCount: 0,
                                originChecked: false, sourceChecked: false,
                                dataShape: '', identity: 'leak|' + to, probeGenerated: false } });
            }
          } catch (e) { noteErr(); }
          return origPost.apply(this, arguments);
        };
        wrap.__jsmdom = true;
        WP.postMessage = wrap;
      } catch (e) { noteErr(); }
    })();
  }

  // Top frame collects relayed findings from cross-origin child frames.
  (function () {
    try {
      if (window.top !== window) return;
      NATIVE_ADD.call(window, 'message', function (ev) {
        try {
          var d = ev && ev.data;
          if (!d || d.__jsmdom_relay !== TOKEN) return;
          if (d.finding && agent.findings.length < MAXF) agent.findings.push(d.finding);
          if (d.confirm) agent.confirmations[d.confirm] = true;
        } catch (e) {}
      }, true);
    } catch (e) {}
  })();

  // ---- source seeding (sources settable from JS, before page scripts run) --
  (function () {
    try {
      for (var i = 0; i < CANARIES.length; i++) {
        var c = CANARIES[i];
        if (!c || !c.token) continue;
        var val = c.value || c.token;
        switch (c.kind) {
          case 'window_name':
            try { window.name = val; } catch (e) {}
            break;
          case 'local_storage':
            try { localStorage.setItem(c.name || 'jsmdom', val); } catch (e) {}
            break;
          case 'session_storage':
            try { sessionStorage.setItem(c.name || 'jsmdom', val); } catch (e) {}
            break;
          case 'cookie':
            try { document.cookie = (c.name || 'jsmdom') + '=' + encodeURIComponent(val) + '; path=/'; } catch (e) {}
            break;
        }
      }
    } catch (e) { noteErr(); }
  })();
})();
`
