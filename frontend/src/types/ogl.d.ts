/**
 * Minimal type stubs for ogl@0.0.116.
 *
 * ogl ships without .d.ts files (it's a small ESM-only WebGL library).
 * These stubs cover only the surface used by LoginFaultyTerminal —
 * Renderer / Program / Mesh / Triangle / Color. Anything outside this
 * surface is intentionally untyped; add fields here as needed.
 */
declare module "ogl" {
  export class Renderer {
    constructor(opts?: { dpr?: number });
    gl: WebGLRenderingContext & {
      canvas: HTMLCanvasElement;
      getExtension(name: string): {
        loseContext?: () => void;
      } | null;
    };
    setSize(width: number, height: number): void;
    render(opts: { scene: unknown }): void;
  }

  export class Program {
    constructor(
      gl: WebGLRenderingContext,
      opts: {
        vertex: string;
        fragment: string;
        uniforms: Record<string, { value: unknown }>;
      },
    );
    uniforms: Record<string, { value: unknown }>;
  }

  export class Triangle {
    constructor(gl: WebGLRenderingContext);
  }

  export class Mesh {
    constructor(gl: WebGLRenderingContext, opts: { geometry: unknown; program: Program });
  }

  export class Color {
    constructor(r: number, g: number, b: number);
    r: number;
    g: number;
    b: number;
  }
}
