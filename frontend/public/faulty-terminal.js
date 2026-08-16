/* AILA FaultyTerminal — self-contained raw-WebGL port of the product's
   hero shader. A CRT/terminal "digit rain" tinted by --accent, with
   scanlines, glitch, chromatic aberration and gentle barrel curvature.
   Designed to be masked by the AILA monogram and screen-blended over the
   midnight background. No external dependencies.

   Usage:
     <div class="aila-terminal-mask" data-faulty-terminal></div>
     <script src="assets/faulty-terminal.js"></script>

   Auto-mounts on any [data-faulty-terminal] element. Honors
   prefers-reduced-motion (renders a single static frame, no RAF loop).
   Exposes window.mountFaultyTerminal(container, opts) -> cleanup fn. */

(function () {
  function hexToRgb(hex) {
    var h = (hex || "").replace("#", "").trim();
    if (h.length === 3) h = h.split("").map(function (c) { return c + c; }).join("");
    var num = parseInt(h, 16);
    if (isNaN(num)) return [1, 1, 1];
    return [((num >> 16) & 255) / 255, ((num >> 8) & 255) / 255, (num & 255) / 255];
  }

  function accentColor() {
    var raw = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim();
    return raw || "#ff5f87";
  }

  var VERT = [
    "attribute vec2 position;",
    "attribute vec2 uv;",
    "varying vec2 vUv;",
    "void main(){ vUv = uv; gl_Position = vec4(position, 0.0, 1.0); }"
  ].join("\n");

  var FRAG = [
    "precision mediump float;",
    "varying vec2 vUv;",
    "uniform float iTime;",
    "uniform vec3  iResolution;",
    "uniform float uScale;",
    "uniform vec2  uGridMul;",
    "uniform float uDigitSize;",
    "uniform float uScanlineIntensity;",
    "uniform float uGlitchAmount;",
    "uniform float uFlickerAmount;",
    "uniform float uNoiseAmp;",
    "uniform float uChromaticAberration;",
    "uniform float uCurvature;",
    "uniform vec3  uTint;",
    "uniform float uBrightness;",
    "uniform float uPageLoadProgress;",
    "float time;",
    "float noise(vec2 p){ return sin(p.x*10.0)*sin(p.y*(3.0+sin(time*0.0909)))+0.2; }",
    "mat2 rot(float a){ float c=cos(a),s=sin(a); return mat2(c,-s,s,c); }",
    "float fbm(vec2 p){",
    "  p*=1.1; float f=0.0; float amp=0.5*uNoiseAmp;",
    "  f+=amp*noise(p); p=rot(time*0.02)*p*2.0; amp*=0.4545;",
    "  f+=amp*noise(p); p=rot(time*0.02)*p*2.0; amp*=0.4545;",
    "  f+=amp*noise(rot(time*0.08)*p); return f;",
    "}",
    "float pattern(vec2 p, out vec2 q, out vec2 r){",
    "  vec2 o1=vec2(1.0), o0=vec2(0.0);",
    "  q=vec2(fbm(p+o1), fbm(rot(0.1*time)*p+o1));",
    "  r=vec2(fbm(rot(0.1)*q+o0), fbm(q+o0));",
    "  return fbm(p+r);",
    "}",
    "float digit(vec2 p){",
    "  vec2 grid=uGridMul*15.0;",
    "  vec2 s=floor(p*grid)/grid;",
    "  p=p*grid; vec2 q,r;",
    "  float intensity=pattern(s*0.1,q,r)*1.3-0.03;",
    "  float cellRandom=fract(sin(dot(s,vec2(12.9898,78.233)))*43758.5453);",
    "  float cellProgress=clamp((uPageLoadProgress-cellRandom*0.8)/0.2,0.0,1.0);",
    "  intensity*=smoothstep(0.0,1.0,cellProgress);",
    "  p=fract(p); p*=uDigitSize;",
    "  float px5=p.x*5.0, py5=(1.0-p.y)*5.0;",
    "  float x=fract(px5), y=fract(py5);",
    "  float i=floor(py5)-2.0, j=floor(px5)-2.0;",
    "  float f=(i*i+j*j)*0.0625;",
    "  float isOn=step(0.1,intensity-f);",
    "  float b=isOn*(0.2+y*0.8)*(0.75+x*0.25);",
    "  return step(0.0,p.x)*step(p.x,1.0)*step(0.0,p.y)*step(p.y,1.0)*b;",
    "}",
    "float onOff(float a,float b,float c){ return step(c,sin(iTime+a*cos(iTime*b)))*uFlickerAmount; }",
    "float displace(vec2 look){",
    "  float y=look.y-mod(iTime*0.25,1.0);",
    "  float w=1.0/(1.0+50.0*y*y);",
    "  return sin(look.y*20.0+iTime)*0.0125*onOff(4.0,2.0,0.8)*(1.0+cos(iTime*60.0))*w;",
    "}",
    "vec3 getColor(vec2 p){",
    "  float bar=step(mod(p.y+time*20.0,1.0),0.2)*0.4+1.0; bar*=uScanlineIntensity;",
    "  float d=displace(p); p.x+=d;",
    "  if(uGlitchAmount!=1.0) p.x+=d*(uGlitchAmount-1.0);",
    "  float middle=digit(p);",
    "  const float off=0.002;",
    "  float sum=digit(p+vec2(-off,-off))+digit(p+vec2(0.0,-off))+digit(p+vec2(off,-off))+",
    "            digit(p+vec2(-off,0.0))+digit(p+vec2(0.0,0.0))+digit(p+vec2(off,0.0))+",
    "            digit(p+vec2(-off,off))+digit(p+vec2(0.0,off))+digit(p+vec2(off,off));",
    "  return vec3(0.9)*middle + sum*0.1*vec3(1.0)*bar;",
    "}",
    "vec2 barrel(vec2 uv){ vec2 c=uv*2.0-1.0; float r2=dot(c,c); c=(1.0+uCurvature*r2)*c; return c*0.5+0.5; }",
    "void main(){",
    "  time=iTime*0.3333;",
    "  vec2 uv=vUv; if(uCurvature!=0.0) uv=barrel(uv);",
    "  vec2 p=uv*uScale;",
    "  vec3 col=getColor(p);",
    "  if(uChromaticAberration!=0.0){",
    "    vec2 ca=vec2(uChromaticAberration)/iResolution.xy;",
    "    col.r=getColor(p+ca).r; col.b=getColor(p-ca).b;",
    "  }",
    "  col*=uTint; col*=uBrightness;",
    "  gl_FragColor=vec4(col,1.0);",
    "}"
  ].join("\n");

  var TUNE = {
    scale: 2.0, gridMul: [2, 1], digitSize: 1.2, timeScale: 0.3,
    scanline: 0.5, glitch: 1.0, flicker: 0.35, noiseAmp: 0.7,
    chroma: 1.5, curvature: 0.1, brightness: 0.55, loadMs: 1800
  };

  function compile(gl, type, src) {
    var sh = gl.createShader(type);
    gl.shaderSource(sh, src);
    gl.compileShader(sh);
    if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
      console.error("FaultyTerminal shader:", gl.getShaderInfoLog(sh));
      return null;
    }
    return sh;
  }

  function mountFaultyTerminal(container, opts) {
    opts = opts || {};
    var cfg = Object.assign({}, TUNE, opts);
    var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var tint = hexToRgb(opts.tint || accentColor());
    var dpr = Math.min(window.devicePixelRatio || 1, 2);

    var canvas = document.createElement("canvas");
    canvas.style.width = "100%";
    canvas.style.height = "100%";
    canvas.style.display = "block";
    container.appendChild(canvas);

    var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    if (!gl) { console.warn("FaultyTerminal: WebGL unavailable"); return function () {}; }

    var prog = gl.createProgram();
    var vs = compile(gl, gl.VERTEX_SHADER, VERT);
    var fs = compile(gl, gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return function () {};
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    gl.useProgram(prog);

    // Fullscreen triangle: positions + uv (uv 0..1 across the screen).
    var buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
      -1, -1, 0, 0,
       3, -1, 2, 0,
      -1,  3, 0, 2
    ]), gl.STATIC_DRAW);
    var locPos = gl.getAttribLocation(prog, "position");
    var locUv = gl.getAttribLocation(prog, "uv");
    gl.enableVertexAttribArray(locPos);
    gl.vertexAttribPointer(locPos, 2, gl.FLOAT, false, 16, 0);
    gl.enableVertexAttribArray(locUv);
    gl.vertexAttribPointer(locUv, 2, gl.FLOAT, false, 16, 8);

    var U = {};
    [
      "iTime", "iResolution", "uScale", "uGridMul", "uDigitSize",
      "uScanlineIntensity", "uGlitchAmount", "uFlickerAmount", "uNoiseAmp",
      "uChromaticAberration", "uCurvature", "uTint", "uBrightness", "uPageLoadProgress"
    ].forEach(function (n) { U[n] = gl.getUniformLocation(prog, n); });

    gl.uniform1f(U.uScale, cfg.scale);
    gl.uniform2f(U.uGridMul, cfg.gridMul[0], cfg.gridMul[1]);
    gl.uniform1f(U.uDigitSize, cfg.digitSize);
    gl.uniform1f(U.uScanlineIntensity, cfg.scanline);
    gl.uniform1f(U.uGlitchAmount, cfg.glitch);
    gl.uniform1f(U.uFlickerAmount, cfg.flicker);
    gl.uniform1f(U.uNoiseAmp, cfg.noiseAmp);
    gl.uniform1f(U.uChromaticAberration, cfg.chroma);
    gl.uniform1f(U.uCurvature, cfg.curvature);
    gl.uniform3f(U.uTint, tint[0], tint[1], tint[2]);
    gl.uniform1f(U.uBrightness, cfg.brightness);
    gl.uniform1f(U.uPageLoadProgress, reduce ? 1 : 0);

    function resize() {
      var w = Math.max(1, container.offsetWidth), h = Math.max(1, container.offsetHeight);
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform3f(U.iResolution, canvas.width, canvas.height, canvas.width / canvas.height);
    }
    var ro = new ResizeObserver(resize);
    ro.observe(container);
    resize();

    var t0 = performance.now();
    var offset = Math.random() * 100;
    var raf = 0;
    function frame(t) {
      gl.uniform1f(U.iTime, ((t * 0.001) + offset) * cfg.timeScale);
      gl.uniform1f(U.uPageLoadProgress, Math.min((t - t0) / cfg.loadMs, 1));
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      raf = requestAnimationFrame(frame);
    }
    if (reduce) {
      gl.uniform1f(U.iTime, 12.0);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    } else {
      raf = requestAnimationFrame(frame);
    }

    return function () {
      cancelAnimationFrame(raf);
      ro.disconnect();
      if (canvas.parentElement === container) container.removeChild(canvas);
      var ext = gl.getExtension("WEBGL_lose_context");
      if (ext) ext.loseContext();
    };
  }

  window.mountFaultyTerminal = mountFaultyTerminal;

  function initAll() {
    document.querySelectorAll("[data-faulty-terminal]").forEach(function (el) {
      if (!el.__ft) el.__ft = mountFaultyTerminal(el);
    });
  }
  if (document.readyState !== "loading") initAll();
  else document.addEventListener("DOMContentLoaded", initAll);
})();
