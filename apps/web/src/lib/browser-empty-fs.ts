export function writeFile(_file: string, _data: string, callback: (error?: Error) => void) {
	callback(new Error("fs.writeFile is unavailable in the browser"));
}
