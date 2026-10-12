import { spawn } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { createServer, type Socket, connect as unixConnect } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { FAKE_AGENT, tempDir, waitFor } from "./helpers.ts";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

describe("gentle-dot command", () => {
	it("rejects stdio mode with self-check before writing any stdout", async () => {
		const child = spawn(process.execPath, [CLI, "--app-channel-stdio", "--self-check"], {
			stdio: ["pipe", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk: Buffer) => {
			stdout += chunk.toString();
		});
		child.stderr.on("data", (chunk: Buffer) => {
			stderr += chunk.toString();
		});
		const code = await new Promise((resolve) => child.on("close", resolve));
		expect(code).toBe(1);
		expect(stdout).toBe("");
		expect(stderr).toMatch(/--app-channel-stdio.*--self-check/);
	});

	it.skipIf(process.platform === "win32")("rejects stdio selection on non-Windows", async () => {
		const child = spawn(process.execPath, [CLI, "--app-channel-stdio"], {
			stdio: ["pipe", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk: Buffer) => {
			stdout += chunk.toString();
		});
		child.stderr.on("data", (chunk: Buffer) => {
			stderr += chunk.toString();
		});
		const code = await new Promise((resolve) => child.on("close", resolve));
		expect(code).toBe(1);
		expect(stdout).toBe("");
		expect(stderr).toMatch(/only supported on Windows/);
	});

	it.skipIf(process.platform !== "win32")(
		"accepts Windows stdio mode without startup text and exits when its peer closes",
		async () => {
			const child = spawn(process.execPath, [CLI, "--app-channel-stdio"], {
				env: {
					...process.env,
					GENTLE_DOT_DATA_DIR: join(tempDir(), "data"),
					GENTLE_DOT_PORT: "0",
					GENTLE_DOT_AGENT_BIN: process.execPath,
					GENTLE_DOT_AGENT_ARGS: JSON.stringify([FAKE_AGENT]),
				},
				stdio: ["pipe", "pipe", "pipe"],
			});
			let stdout = "";
			let stderr = "";
			let pendingFrames = "";
			child.stdout.on("data", (chunk: Buffer) => {
				stdout += chunk.toString();
				pendingFrames += chunk.toString();
				for (let end = pendingFrames.indexOf("\n"); end >= 0; end = pendingFrames.indexOf("\n")) {
					const line = pendingFrames.slice(0, end);
					pendingFrames = pendingFrames.slice(end + 1);
					try {
						const frame = JSON.parse(line);
						if (frame.kind === "request")
							child.stdin.write(
								`${JSON.stringify({
									kind: "response",
									id: frame.id,
									result: null,
								})}\n`,
							);
					} catch {
						/* Startup text must fail the assertions below, not the event callback. */
					}
				}
			});
			child.stderr.on("data", (chunk: Buffer) => {
				stderr += chunk.toString();
			});
			const exited = new Promise<number | null>((resolve) => child.on("close", resolve));
			let code: number | null = null;
			try {
				// A real peer request must reach the daemon handler and return a framed answer.
				await waitFor(() => stdout.includes('"method":"secret_get"'), 15_000);
				child.stdin.write(`${JSON.stringify({ kind: "request", id: 71, method: "computer_unregister" })}\n`);
				await waitFor(
					() =>
						stdout.split("\n").some((line) => {
							try {
								const frame = JSON.parse(line);
								return frame.kind === "response" && frame.id === 71 && frame.result !== undefined;
							} catch {
								return false;
							}
						}),
					15_000,
				);
				const answer = stdout
					.split("\n")
					.filter(Boolean)
					.map((line) => JSON.parse(line))
					.find((frame) => frame.kind === "response" && frame.id === 71 && frame.result !== undefined);
				expect(answer).toEqual({ kind: "response", id: 71, result: {} });
				expect(stdout).not.toContain("Gentle Dot is running");
				expect(stdout).not.toContain("the access key is in");
				for (const line of stdout.trim().split("\n")) expect(() => JSON.parse(line)).not.toThrow();
				child.stdin.end();
				let closed = false;
				void exited.then((value) => {
					code = value;
					closed = true;
				});
				await waitFor(() => closed, 15_000);
			} catch (error) {
				throw new Error(`stdio exchange failed: stdout=${stdout}; stderr=${stderr}`, { cause: error });
			} finally {
				child.kill("SIGTERM");
				await exited;
			}
			expect(code).toBe(0);
			expect(stdout).not.toContain("Gentle Dot is running");
			expect(stderr).toContain("the desktop app's channel closed; stopping the assistant");
		},
	);

	it("keeps the access key out of redirected output, such as a log file", async () => {
		const dataDir = join(tempDir(), "data");
		const child = spawn(process.execPath, [CLI], {
			env: {
				...process.env,
				GENTLE_DOT_DATA_DIR: dataDir,
				GENTLE_DOT_PORT: "0",
				GENTLE_DOT_AGENT_BIN: process.execPath,
				GENTLE_DOT_AGENT_ARGS: JSON.stringify([FAKE_AGENT]),
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		let output = "";
		child.stdout.on("data", (chunk: Buffer) => {
			output += chunk.toString();
		});
		const exited = new Promise((resolve) => child.on("close", resolve));
		try {
			await waitFor(() => output.includes("Gentle Dot is running"), 15_000);
		} finally {
			child.kill("SIGTERM");
			await exited;
		}
		const token = readFileSync(join(dataDir, "token"), "utf8").trim();
		expect(output).not.toContain(token);
		expect(output).toContain(`the access key is in ${join(dataDir, "token")}`);
		expect(statSync(dataDir).mode & 0o777).toBe(0o700);
	});

	it.skipIf((process.getuid?.() ?? 0) === 0)(
		"refuses server mode it cannot keep: GENTLE_DOT_VPS as a user that is not root (S25.8)",
		async () => {
			const dataDir = join(tempDir(), "data");
			const child = spawn(process.execPath, [CLI], {
				env: {
					...process.env,
					GENTLE_DOT_VPS: "1",
					GENTLE_DOT_DATA_DIR: dataDir,
					GENTLE_DOT_PORT: "0",
					GENTLE_DOT_AGENT_BIN: process.execPath,
					GENTLE_DOT_AGENT_ARGS: JSON.stringify([FAKE_AGENT]),
				},
				stdio: ["ignore", "pipe", "pipe"],
			});
			let output = "";
			for (const stream of [child.stdout, child.stderr])
				stream.on("data", (chunk: Buffer) => {
					output += chunk.toString();
				});
			const code = await Promise.race([
				new Promise((resolve) => child.on("close", resolve)),
				new Promise((resolve) => setTimeout(() => resolve("still running"), 10_000)),
			]);
			if (code === "still running") child.kill("SIGTERM");
			expect(code).toBe(1);
			expect(output).toMatch(/failed to start: Server mode .* root/);
			expect(output).not.toContain("Gentle Dot is running");
		},
	);

	it("a daemon launched with the app's channel exits when the app goes (S35.2, #22)", async () => {
		const dataDir = join(tempDir(), "data");
		const { app, daemon } = await socketPair();
		const child = spawn(process.execPath, [CLI], {
			env: {
				...process.env,
				GENTLE_DOT_DATA_DIR: dataDir,
				GENTLE_DOT_PORT: "0",
				GENTLE_DOT_AGENT_BIN: process.execPath,
				GENTLE_DOT_AGENT_ARGS: JSON.stringify([FAKE_AGENT]),
			},
			stdio: ["ignore", "pipe", "pipe", daemon],
		});
		daemon.destroy();
		let output = "";
		const collect = (chunk: Buffer) => {
			output += chunk.toString();
		};
		child.stdout?.on("data", collect);
		child.stderr?.on("data", collect);
		const exited = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
		try {
			// The daemon is up once it asks the app for something (the connectors' integrity key).
			await new Promise((resolve) => app.once("data", resolve));
			// The app quits, crashes, or is killed: the kernel closes its end of the pair.
			app.destroy();
			expect(await exited).toBe(0);
		} finally {
			child.kill("SIGKILL");
		}
		expect(output).toContain("the desktop app's channel closed; stopping the assistant");
	});
});

/** A connected pair of Unix sockets (Node has no socketpair): the app's end and the daemon's. */
async function socketPair(): Promise<{ app: Socket; daemon: Socket }> {
	const path = join(tempDir(), "pair.sock");
	const server = createServer();
	await new Promise<void>((done) => server.listen(path, done));
	const accepted = new Promise<Socket>((resolve) => server.once("connection", resolve));
	const daemon = unixConnect(path);
	await new Promise((resolve) => daemon.once("connect", resolve));
	const app = await accepted;
	server.close();
	return { app, daemon };
}
