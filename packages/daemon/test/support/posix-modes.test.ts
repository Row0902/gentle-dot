// The two branches of the mode helper, proven without a Windows machine: the platform is injectable,
// so the Windows skip path runs anywhere.
import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { tempDir } from "../helpers.ts";
import {
	expectPosixExecutable,
	expectPosixLstatMode,
	expectPosixMode,
	hasPosixModes,
} from "./posix-modes.ts";

describe("posix mode helper", () => {
	it("knows which platforms carry POSIX mode bits", () => {
		expect(hasPosixModes("linux")).toBe(true);
		expect(hasPosixModes("darwin")).toBe(true);
		expect(hasPosixModes("win32")).toBe(false);
	});

	it.skipIf(process.platform === "win32")("asserts the real mode bits on a POSIX host", () => {
		const file = join(tempDir(), "private");
		writeFileSync(file, "x");
		chmodSync(file, 0o600);
		expectPosixMode(file, 0o600, "linux");
		expectPosixLstatMode(file, 0o600, "linux");
		expect(() => expectPosixMode(file, 0o644, "linux")).toThrow();
		chmodSync(file, 0o755);
		expectPosixExecutable(file, "linux");
		chmodSync(file, 0o644);
		expect(() => expectPosixExecutable(file, "linux")).toThrow();
	});

	it("skips and warns on every gated assertion, so no skip is silently green", () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			const file = join(tempDir(), "private");
			writeFileSync(file, "x");
			// The real mode can never match on Windows; the helper must not throw.
			expect(() => expectPosixMode(file, 0o600, "win32")).not.toThrow();
			expect(() => expectPosixLstatMode(file, 0o600, "win32")).not.toThrow();
			expect(() => expectPosixMode(file, 0o644, "win32")).not.toThrow();
			expect(() => expectPosixExecutable(file, "win32")).not.toThrow();
			// Every gated assertion that skips must say so: a once-per-process warning leaves the
			// later ones green in silence, and the guarantee must hold per test, not per run.
			expect(warn).toHaveBeenCalledTimes(4);
			for (const call of warn.mock.calls) {
				expect(call[0]).toContain("odd/tasks/windows-port.md");
				expect(call[0]).toContain("ACL");
			}
		} finally {
			warn.mockRestore();
		}
	});
});
