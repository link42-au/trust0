import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
	testDir: "./tests/e2e",
	fullyParallel: true,
	retries: 0,
	workers: 1,
	use: {
		baseURL: "http://127.0.0.1:4373",
		trace: "retain-on-failure",
	},
	projects: [
		{
			name: "chromium",
			use: { ...devices["Desktop Chrome"] },
		},
	],
	webServer: {
		command: "pnpm dev --host 127.0.0.1 --port 4373",
		url: "http://127.0.0.1:4373",
		reuseExistingServer: false,
	},
});
