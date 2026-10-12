// Shared protocol bounds only: these tests do not prove stdio bootstrap or native inheritance.
import { Duplex } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppChannel } from "../src/app-channel.ts";

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
