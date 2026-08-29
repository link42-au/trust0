function unsupported(name: string) {
	return () => {
		throw new Error(`${name} is unavailable in the browser`);
	};
}

const nodeUnsupported = new Proxy({}, {
	get(_target, property) {
		return unsupported(String(property));
	},
});

export default nodeUnsupported;
