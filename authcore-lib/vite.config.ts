import { defineConfig } from 'vite';
import { resolve } from 'path';
import dts from 'vite-plugin-dts';

export default defineConfig({
  plugins: [
    dts({
      insertTypesEntry: true, // Auto-generates the "types" entry in package.json
    }),
  ],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'AuthCore',
      formats: ['es', 'cjs'],       // Dual output: ESM + CJS
      fileName: (format) => `index.${format === 'es' ? 'mjs' : 'js'}`,
    },
    rollupOptions: {
      // Externalize all Node.js and peer dependencies so they are
      // not bundled into the library output
      external: [
        'express',
        'jsonwebtoken',
        'bcrypt',
        'mongoose',
      ],
    },
    sourcemap: true,
    outDir: 'dist',
    emptyOutDir: true,
  },
});
