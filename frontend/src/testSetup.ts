class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

globalThis.ResizeObserver = ResizeObserverStub;

Object.defineProperties(HTMLElement.prototype, {
  clientWidth: { configurable: true, value: 1024 },
  offsetWidth: { configurable: true, value: 1024 },
});
