import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Mock } from "vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type MountFaultyTerminal = (container: HTMLElement, opts?: Record<string, unknown>) => () => void;

interface MediaQueryStub {
	matches: boolean;
}

/** The subset of `window` the public script reads. Passed as the script's
 * `window` parameter so no globals are mutated. */
interface PublicScriptWindow {
	devicePixelRatio: number;
	matchMedia: (query: string) => MediaQueryStub;
	mountFaultyTerminal?: MountFaultyTerminal;
}

interface WebGLStub {
	gl: Record<string, unknown>;
	loseContext: Mock;
}

const PUBLIC_SCRIPT = readFileSync(resolve(process.cwd(), "public/faulty-terminal.js"), "utf8");

let reducedMotion = false;
let documentHidden = false;
let currentTimestamp = 0;
let drawTimes: number[] = [];
let nextRafId = 1;
let rafCallbacks = new Map<number, FrameRequestCallback>();
let cleanups: Array<() => void> = [];
let publicWindow: PublicScriptWindow;
let resizeObserve: Mock;
let resizeDisconnect: Mock;
let webgl: WebGLStub;

function createWebGLStub(): WebGLStub {
	const loseContext = vi.fn();
	const gl = {
		VERTEX_SHADER: 1,
		FRAGMENT_SHADER: 2,
		COMPILE_STATUS: 3,
		ARRAY_BUFFER: 4,
		STATIC_DRAW: 5,
		FLOAT: 6,
		TRIANGLES: 7,
		createShader: vi.fn(() => ({})),
		shaderSource: vi.fn(),
		compileShader: vi.fn(),
		getShaderParameter: vi.fn(() => true),
		getShaderInfoLog: vi.fn(() => ""),
		createProgram: vi.fn(() => ({})),
		attachShader: vi.fn(),
		linkProgram: vi.fn(),
		useProgram: vi.fn(),
		createBuffer: vi.fn(() => ({})),
		bindBuffer: vi.fn(),
		bufferData: vi.fn(),
		getAttribLocation: vi.fn(() => 0),
		enableVertexAttribArray: vi.fn(),
		vertexAttribPointer: vi.fn(),
		getUniformLocation: vi.fn(() => ({})),
		uniform1f: vi.fn(),
		uniform2f: vi.fn(),
		uniform3f: vi.fn(),
		viewport: vi.fn(),
		drawArrays: vi.fn(() => {
			drawTimes.push(currentTimestamp);
		}),
		getExtension: vi.fn((name: string) => (name === "WEBGL_lose_context" ? { loseContext } : null)),
	};

	return { gl, loseContext };
}

function requestFrame(callback: FrameRequestCallback): number {
	const id = nextRafId;
	nextRafId += 1;
	rafCallbacks.set(id, callback);
	return id;
}

function cancelFrame(id: number): void {
	rafCallbacks.delete(id);
}

/** Runs one synthetic animation frame at `timestamp`. Callbacks scheduled
 * during this frame run on the next call, like a real RAF tick. */
function flushRaf(timestamp: number): void {
	currentTimestamp = timestamp;
	const callbacks = [...rafCallbacks.values()];
	rafCallbacks.clear();
	for (const callback of callbacks) callback(timestamp);
}

function mountTerminal(): { container: HTMLElement; cleanup: () => void } {
	const mount = publicWindow.mountFaultyTerminal;
	if (!mount) throw new Error("The public script did not expose mountFaultyTerminal");

	const container = document.createElement("div");
	document.body.appendChild(container);
	const dispose = mount(container, { tint: "#ff5f87" });

	let disposed = false;
	const cleanup = () => {
		if (disposed) return;
		disposed = true;
		dispose();
	};
	cleanups.push(cleanup);

	return { container, cleanup };
}

function drawsInSecond(second: number): number {
	const start = second * 1000;
	return drawTimes.filter((timestamp) => timestamp >= start && timestamp < start + 1000).length;
}

beforeEach(() => {
	reducedMotion = false;
	documentHidden = false;
	currentTimestamp = 0;
	drawTimes = [];
	nextRafId = 1;
	rafCallbacks = new Map();
	cleanups = [];
	resizeObserve = vi.fn();
	resizeDisconnect = vi.fn();
	webgl = createWebGLStub();
	document.body.replaceChildren();

	Object.defineProperty(document, "hidden", { configurable: true, get: () => documentHidden });
	vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockImplementation(() => webgl.gl as never);

	const observeStub = resizeObserve;
	const disconnectStub = resizeDisconnect;
	class ResizeObserverStub {
		observe = observeStub;
		disconnect = disconnectStub;
	}

	publicWindow = {
		devicePixelRatio: 1,
		matchMedia: () => ({ matches: reducedMotion }),
	};

	const execute = new Function(
		"window",
		"document",
		"requestAnimationFrame",
		"cancelAnimationFrame",
		"ResizeObserver",
		PUBLIC_SCRIPT,
	);
	execute(publicWindow, document, requestFrame, cancelFrame, ResizeObserverStub);
});

afterEach(() => {
	for (const cleanup of cleanups) cleanup();
	Reflect.deleteProperty(document, "hidden");
	document.body.replaceChildren();
	vi.restoreAllMocks();
});

describe("public faulty-terminal animation", () => {
	it("caps observable WebGL draws at 30 per second on a synthetic RAF clock", () => {
		const { cleanup } = mountTerminal();

		// 120 callbacks per second makes an uncapped loop fail decisively.
		for (let frame = 0; frame < 360; frame += 1) {
			flushRaf(frame * (1000 / 120));
		}

		for (let second = 0; second < 3; second += 1) {
			expect(drawsInSecond(second)).toBeGreaterThan(0);
			expect(drawsInSecond(second)).toBeLessThanOrEqual(30);
		}
		expect(drawTimes.length).toBeLessThanOrEqual(90);
		cleanup();
	});

	it("draws one static frame for reduced motion without scheduling RAF", () => {
		reducedMotion = true;
		const { cleanup } = mountTerminal();

		expect(drawTimes).toHaveLength(1);
		expect(rafCallbacks.size).toBe(0);

		flushRaf(16);
		flushRaf(1000);
		expect(drawTimes).toHaveLength(1);
		expect(rafCallbacks.size).toBe(0);
		cleanup();
	});

	it("stops while hidden and resumes with a visible frame", () => {
		const { cleanup } = mountTerminal();
		flushRaf(0);
		expect(drawTimes).toHaveLength(1);
		expect(rafCallbacks.size).toBe(1);

		documentHidden = true;
		document.dispatchEvent(new Event("visibilitychange"));
		expect(rafCallbacks.size).toBe(0);

		flushRaf(16);
		flushRaf(1000);
		expect(drawTimes).toHaveLength(1);

		documentHidden = false;
		document.dispatchEvent(new Event("visibilitychange"));
		expect(rafCallbacks.size).toBe(1);
		flushRaf(2000);
		expect(drawTimes).toHaveLength(2);
		cleanup();
	});

	it("cancels RAF and removes its visibility listener, observer, canvas, and WebGL context on cleanup", () => {
		const addListener = vi.spyOn(document, "addEventListener");
		const removeListener = vi.spyOn(document, "removeEventListener");
		const { container, cleanup } = mountTerminal();
		flushRaf(0);
		expect(rafCallbacks.size).toBe(1);

		const added = addListener.mock.calls.find(([type]) => type === "visibilitychange");
		expect(added).toBeDefined();

		cleanup();

		expect(rafCallbacks.size).toBe(0);
		expect(resizeObserve).toHaveBeenCalledTimes(1);
		expect(resizeDisconnect).toHaveBeenCalledTimes(1);
		expect(webgl.loseContext).toHaveBeenCalledTimes(1);
		expect(container.querySelector("canvas")).toBeNull();
		const removed = removeListener.mock.calls.find(([type]) => type === "visibilitychange");
		expect(removed?.[1]).toBe(added?.[1]);

		documentHidden = false;
		document.dispatchEvent(new Event("visibilitychange"));
		flushRaf(2000);
		expect(drawTimes).toHaveLength(1);
		expect(rafCallbacks.size).toBe(0);
	});
});
