class BrowserIrcClient {
	constructor() {
		throw new Error("IRC verification requires the verification proxy in the browser");
	}
}

export default {
	Client: BrowserIrcClient,
};
