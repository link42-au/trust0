import { sveltekit } from "@sveltejs/kit/vite";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
	plugins: [sveltekit()],
	resolve: {
		alias: {
			crypto: fileURLToPath(new URL("./src/lib/browser-node-unsupported.ts", import.meta.url)),
			dns: fileURLToPath(new URL("./src/lib/browser-node-unsupported.ts", import.meta.url)),
			fs: fileURLToPath(new URL("./src/lib/browser-empty-fs.ts", import.meta.url)),
			"irc-upd": fileURLToPath(new URL("./src/lib/browser-irc-upd.ts", import.meta.url)),
		},
	},
	build: {
		rollupOptions: {
			output: {
				manualChunks(id) {
					if (id.includes("/openpgp/") || id.includes("/@openpgp/")) return "openpgp";
					if (id.includes("/hash-wasm/")) return "hash-wasm";
				},
			},
		},
	},
});
