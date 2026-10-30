/**
 * jsdom has no `window.matchMedia`, and the collector specs spy on it. Installed as an inert,
 * honest implementation (`matches` is false) before any spec is imported; a spec that needs a
 * query to match stubs it itself.
 */
if (typeof window !== 'undefined' && typeof window.matchMedia !== 'function') {
    window.matchMedia = ((query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
    })) as typeof window.matchMedia;
}
