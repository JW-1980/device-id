import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// The collectors are consumed through the same `@device-id` alias in the host applications.
export default defineConfig({
    resolve: {
        alias: {
            '@device-id': fileURLToPath(new URL('./resources/js', import.meta.url)),
        },
    },
    test: {
        environment: 'jsdom',
        globals: true,
        setupFiles: ['./resources/js/testing/vitestSetup.ts'],
        include: ['resources/js/**/*.spec.ts'],
    },
});
