// Shared bounds and in-memory stdio adapter tests do not prove native bootstrap or inheritance.
import { Duplex, PassThrough, Writable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppChannel, openStdioChannel } from "../src/app-channel.ts";

const MAX_FRAME = 1024 * 1024;
const channels: AppChannel[] = [];
afterEach(() => {
	for (const channel of channels.splice(0)) channel.close();
});

function setup() {
	const output: string[] = [];
	const stream = new Duplex({
		read() {},
		write(chunk, _encoding, done) {
			output.push(String(chunk));
			done();
		},
	});
	const log = vi.fn();
	const channel = new AppChannel(stream, { log });
	const handler = vi.fn(() => ({ ok: true }));
	channel.handler = handler;
	channels.push(channel);
	return { stream, channel, handler, log, output };
}

function request(bytes: number, character = "a", id = 1): string {
	const empty = JSON.stringify({ kind: "request", id, method: "test", params: "" });
	const available = bytes - Buffer.byteLength(empty);
	const width = Buffer.byteLength(character);
	const payload = character.repeat(Math.floor(available / width)) + "a".repeat(available % width);
	const line = JSON.stringify({ kind: "request", id, method: "test", params: payload });
	expect(Buffer.byteLength(line)).toBe(bytes);
	return line;
}

const settle = () => new Promise<void>((resolve) => setImmediate(resolve));

function stdioSetup(writer?: Writable) {
	const reader = new PassThrough({ autoDestroy: false });
	const output = new PassThrough();
	const bytes: string[] = [];
	output.on("data", (chunk) => bytes.push(String(chunk)));
	const log = vi.fn();
	const channel = openStdioChannel({
		selected: true,
		platform: "win32",
		reader,
		writer: writer ?? output,
		log,
	});
	expect(channel).toBeDefined();
	if (!channel) throw new Error("selected Windows bootstrap returned no channel");
	channels.push(channel);
	return { channel, reader, output, bytes, log };
}

describe("explicit Windows stdio adapter", () => {
	it("requires explicit selection and refuses selected off-platform bootstrap", () => {
		const reader = new PassThrough();
		const writer = new PassThrough();
		expect(openStdioChannel({ selected: false, platform: "win32", reader, writer })).toBeUndefined();
		expect(reader.listenerCount("data")).toBe(0);
		expect(() => openStdioChannel({ selected: true, platform: "linux", reader, writer })).toThrow(/Windows/);
		expect(reader.destroyed).toBe(false);
		expect(writer.destroyed).toBe(false);
	});

	it("frames requests and responses bidirectionally without diagnostic output", async () => {
		const { channel, reader, bytes, log } = stdioSetup();
		channel.handler = (method, params) => ({ method, params });
		const pending = channel.request("approve", { title: "test" }, 1000);
		expect(JSON.parse(bytes[0] ?? "")).toMatchObject({ kind: "request", id: 1, method: "approve" });
		reader.write('not JSON\n{"kind":"response","id":1,"result":{"approved":true}}\n');
		await expect(pending).resolves.toEqual({ approved: true });
		reader.write('{"kind":"request","id":9,"method":"command","params":{"text":"😀"}}\n');
		await settle();
		expect(bytes.map((line) => JSON.parse(line))).toHaveLength(2);
		expect(JSON.parse(bytes[1] ?? "")).toEqual({
			kind: "response",
			id: 9,
			result: { method: "command", params: { text: "😀" } },
		});
		expect(log).toHaveBeenCalledOnce();
	});

	it.each(["eof", "read error", "write error", "reader close", "writer close", "local close"])(
		"revokes on %s without destroying borrowed endpoints or leaking listeners",
		async (event) => {
			const { channel, reader, output } = stdioSetup();
			const closed = vi.fn();
			channel.onClose(closed);
			const pending = channel.request("approve", {}, 1000);
			const refused = expect(pending).rejects.toThrow(/closed/);
			if (event === "eof") reader.end();
			else if (event === "read error") reader.emit("error", new Error("read failed"));
			else if (event === "write error") output.emit("error", new Error("write failed"));
			else if (event === "reader close") reader.emit("close");
			else if (event === "writer close") output.emit("close");
			else channel.close();
			await refused;
			await settle();
			await settle(); // Release the guard one turn after endpoint completion, not adapter close.
			channel.close();
			expect(channel.connected).toBe(false);
			expect(closed).toHaveBeenCalledOnce();
			expect(reader.destroyed).toBe(false);
			expect(output.destroyed).toBe(false);
			expect(output.writableEnded).toBe(false);
			for (const name of ["data", "end", "error", "close"]) expect(reader.listenerCount(name)).toBe(0);
			for (const name of ["error", "close", "finish"]) expect(output.listenerCount(name)).toBe(0);
		},
	);

	it("rejects oversized input through the production adapter before dispatch", async () => {
		const { channel, reader, bytes } = stdioSetup();
		const handler = vi.fn();
		channel.handler = handler;
		reader.write(`${request(MAX_FRAME + 1, "😀")}\n`);
		await settle();
		expect(channel.connected).toBe(false);
		expect(handler).not.toHaveBeenCalled();
		expect(bytes).toEqual([]);
	});

	it("accepts an exact-boundary frame with fragmented UTF-8 through the adapter", async () => {
		const { channel, reader, bytes } = stdioSetup();
		const handler = vi.fn(() => ({ ok: true }));
		channel.handler = handler;
		const line = request(MAX_FRAME, "😀");
		const input = Buffer.from(line);
		const split = input.indexOf(Buffer.from("😀")) + 2;
		reader.write(input.subarray(0, split));
		await settle();
		reader.write(input.subarray(split));
		await settle();
		expect(handler).not.toHaveBeenCalled();
		reader.write("\n");
		await settle();
		expect(channel.connected).toBe(true);
		expect(handler).toHaveBeenCalledExactlyOnceWith("test", JSON.parse(line).params);
		expect(bytes.map((value) => JSON.parse(value))).toEqual([
			{ kind: "response", id: 1, result: { ok: true } },
		]);
	});

	it("refuses oversized unterminated UTF-8 through the adapter", async () => {
		const { channel, reader } = stdioSetup();
		reader.write(request(MAX_FRAME + 1, "😀"));
		await settle();
		expect(channel.connected).toBe(false);
	});

	it("waits for write completion, then propagates a callback error", async () => {
		let complete: ((error?: Error | null) => void) | undefined;
		const writes = vi.fn();
		const writer = new Writable({
			write(_chunk, _encoding, done) {
				writes();
				complete = done;
			},
		});
		const { channel } = stdioSetup(writer);
		const first = channel.request("first", {}, 1000);
		const second = channel.request("second", {}, 1000);
		const results = Promise.allSettled([first, second]);
		expect(writes).toHaveBeenCalledOnce();
		complete?.(new Error("sink failed"));
		await results;
		expect(channel.connected).toBe(false);
		expect(writes).toHaveBeenCalledOnce();
	});

	it("serializes successful writes behind a backpressured endpoint", async () => {
		const callbacks: Array<(error?: Error | null) => void> = [];
		const writer = new Writable({
			highWaterMark: 1,
			write(_chunk, _encoding, done) {
				callbacks.push(done);
			},
		});
		const { channel, reader } = stdioSetup(writer);
		const first = channel.request("first", {}, 1000);
		const second = channel.request("second", {}, 1000);
		expect(callbacks).toHaveLength(1);
		callbacks[0]?.();
		await settle();
		expect(callbacks).toHaveLength(2);
		callbacks[1]?.();
		reader.write('{"kind":"response","id":1,"result":1}\n{"kind":"response","id":2,"result":2}\n');
		await expect(Promise.all([first, second])).resolves.toEqual([1, 2]);
		expect(channel.connected).toBe(true);
	});

	it.each([false, true])("stdio late-settlement guard survives close (failure=%s)", async (failure) => {
		let complete: ((error?: Error | null) => void) | undefined;
		const writer = new Writable({
			autoDestroy: false,
			write(_chunk, _encoding, done) {
				complete = done;
			},
		});
		const { channel } = stdioSetup(writer);
		const closed = vi.fn();
		channel.onClose(closed);
		const pending = channel.request("delayed", {}, 1000);
		const rejected = expect(pending).rejects.toThrow(/closed/);
		channel.close();
		await rejected;
		await settle();
		await settle();
		const productionGuards = writer.listenerCount("error");
		// Observe the real Writable callback/error sequence without crashing RED when its guard is absent.
		const observed = vi.fn();
		writer.on("error", observed);
		complete?.(failure ? new Error("late sink failure") : undefined);
		await settle();
		await settle();
		expect(observed).toHaveBeenCalledTimes(failure ? 1 : 0);
		expect(productionGuards).toBe(1);
		expect(writer.listenerCount("error")).toBe(1); // Only our external observer remains.
		writer.off("error", observed);
		expect(writer.destroyed).toBe(false);
		expect(writer.writableEnded).toBe(false);
		expect(closed).toHaveBeenCalledOnce();
	});

	it("revokes instead of accumulating unbounded output behind a stalled writer", async () => {
		const writer = new Writable({ write() {} });
		const { channel } = stdioSetup(writer);
		const pending = Array.from({ length: 4 }, () =>
			channel.request("large", "a".repeat(MAX_FRAME / 2), 1000),
		);
		const results = await Promise.allSettled(pending);
		expect(channel.connected).toBe(false);
		expect(results.every((result) => result.status === "rejected")).toBe(true);
	});
});

describe("shared AppChannel incoming UTF-8 bounds", () => {
	it.each(["a", "😀"])("refuses a complete oversized %s frame before dispatch", async (character) => {
		const { stream, channel, handler, log, output } = setup();
		stream.push(Buffer.from(`${request(MAX_FRAME + 1, character)}\n`));
		await settle();
		expect(channel.connected).toBe(false);
		expect(handler).not.toHaveBeenCalled();
		expect(output).toEqual([]);
		expect(log).toHaveBeenCalledWith(expect.stringContaining("too long"));
	});

	it("refuses oversized unterminated multibyte input despite shorter string length", async () => {
		const { stream, channel, handler } = setup();
		const line = request(MAX_FRAME + 1, "😀");
		expect(line.length).toBeLessThan(MAX_FRAME);
		stream.push(Buffer.from(line));
		await settle();
		expect(channel.connected).toBe(false);
		expect(handler).not.toHaveBeenCalled();
	});

	it.each(["a", "😀"])(
		"accepts exactly MAX_FRAME bytes of %s without counting newline",
		async (character) => {
			const { stream, channel, handler, output } = setup();
			stream.push(Buffer.from(request(MAX_FRAME, character)));
			await settle();
			expect(channel.connected).toBe(true);
			expect(handler).not.toHaveBeenCalled();
			stream.push(Buffer.from("\n"));
			await settle();
			expect(channel.connected).toBe(true);
			expect(handler).toHaveBeenCalledOnce();
			expect(output.map((line) => JSON.parse(line))).toEqual([
				{ kind: "response", id: 1, result: { ok: true } },
			]);
		},
	);

	it("preserves split UTF-8 codepoints and fragmented lines at the exact boundary", async () => {
		const { stream, channel, handler } = setup();
		const line = request(MAX_FRAME, "😀");
		const bytes = Buffer.from(`${line}\n`);
		const emoji = bytes.indexOf(Buffer.from("😀"));
		for (const [start, end] of [
			[0, emoji + 1],
			[emoji + 1, emoji + 3],
			[emoji + 3, bytes.length - 2],
			[bytes.length - 2, bytes.length],
		]) {
			stream.push(bytes.subarray(start, end));
			await settle();
		}
		expect(channel.connected).toBe(true);
		expect(handler).toHaveBeenCalledExactlyOnceWith("test", JSON.parse(line).params);
	});

	it("accepts multiple individually bounded frames in one oversized aggregate chunk", async () => {
		const { stream, channel, handler } = setup();
		stream.push(Buffer.from(`${request(MAX_FRAME, "a", 1)}\n${request(MAX_FRAME, "😀", 2)}\n`));
		await settle();
		expect(channel.connected).toBe(true);
		expect(handler).toHaveBeenCalledTimes(2);
	});

	it("keeps malformed JSON log/ignore and blank-line behavior without protocol diagnostics", async () => {
		const { stream, channel, handler, log, output } = setup();
		stream.push(Buffer.from(`not JSON\n \t\n\n${request(100)}\n`));
		await settle();
		expect(channel.connected).toBe(true);
		expect(handler).toHaveBeenCalledOnce();
		expect(log).toHaveBeenCalledExactlyOnceWith(expect.stringContaining("not JSON; ignored"));
		expect(output.map((line) => JSON.parse(line))).toEqual([
			{ kind: "response", id: 1, result: { ok: true } },
		]);
	});
});
