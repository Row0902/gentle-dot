import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { type AddressInfo, createServer } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PROTOCOL_VERSION, type ServerMessage } from "@gentle-dot/protocol";
import { expect, it } from "vitest";
import WebSocket from "ws";
import { FAKE_AGENT, tempDir, waitFor } from "./helpers.ts";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

// Selected-mode stdout is exclusively frames, so it cannot advertise port 0.
// Probe an OS-selected free loopback port and release it just before spawning.
// A bind race fails this test; the isolated hello token cannot authenticate elsewhere.
async function availablePort(): Promise<number> {
	const server = createServer();
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", resolve);
	});
	const port = (server.address() as AddressInfo).port;
	await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
	return port;
}

it.skipIf(process.platform !== "win32")(
	"streams chat, reloads history, serves the private channel, and stops on stdio EOF",
	{ timeout: 60_000 },
	async () => {
		const dataDir = join(tempDir(), "data");
		const port = await availablePort();
		const child = spawn(process.execPath, [CLI, "--app-channel-stdio"], {
			env: {
				...process.env,
				GENTLE_DOT_DATA_DIR: dataDir,
				GENTLE_DOT_HOST: "127.0.0.1",
				GENTLE_DOT_PORT: String(port),
				GENTLE_DOT_AGENT_BIN: process.execPath,
				GENTLE_DOT_AGENT_ARGS: JSON.stringify([FAKE_AGENT]),
				GENTLE_DOT_CONVERSATIONS: "0",
			},
			stdio: ["pipe", "pipe", "pipe"],
		});
		const frames: Record<string, unknown>[] = [];
		const invalidLines: string[] = [];
		let pending = "";
		let stderr = "";
		let spawnError: Error | undefined;
		child.on("error", (error) => {
			spawnError = error;
		});
		child.stdout.on("data", (chunk: Buffer) => {
			pending += chunk.toString();
			for (let end = pending.indexOf("\n"); end >= 0; end = pending.indexOf("\n")) {
				const line = pending.slice(0, end);
				pending = pending.slice(end + 1);
				try {
					const frame = JSON.parse(line) as Record<string, unknown>;
					frames.push(frame);
					if (frame.kind === "request")
						child.stdin.write(`${JSON.stringify({ kind: "response", id: frame.id, result: null })}\n`);
				} catch {
					invalidLines.push(line);
				}
			}
		});
		child.stderr.on("data", (chunk: Buffer) => {
			stderr += chunk.toString();
		});
		let closed = false;
		let exitCode: number | null = null;
		const exited = new Promise<void>((resolve) => {
			child.on("close", (code) => {
				exitCode = code;
				closed = true;
				resolve();
			});
		});
		const sockets: WebSocket[] = [];
		const connect = async () => {
			const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
			sockets.push(ws);
			const messages: ServerMessage[] = [];
			ws.on("message", (data) => messages.push(JSON.parse(String(data)) as ServerMessage));
			await new Promise<void>((resolve, reject) => {
				ws.once("open", resolve);
				ws.once("error", reject);
			});
			ws.send(
				JSON.stringify({
					type: "hello",
					token: readFileSync(join(dataDir, "token"), "utf8").trim(),
					protocol: PROTOCOL_VERSION,
				}),
			);
			await waitFor(() => messages.some((message) => message.type === "ready"), 10_000);
			return { ws, messages };
		};
		try {
			await waitFor(() => existsSync(join(dataDir, "token")), 15_000);
			const deadline = Date.now() + 15_000;
			for (;;) {
				if (closed || spawnError) throw new Error("CLI exited before listening");
				try {
					const health = await fetch(`http://127.0.0.1:${port}/health`, {
						signal: AbortSignal.timeout(1000),
					});
					if (health.ok && (await health.json()).agentState === "idle") break;
				} catch {
					// The token is created before the HTTP listener starts.
				}
				if (Date.now() >= deadline) throw new Error("CLI did not become healthy");
				await new Promise((resolve) => setTimeout(resolve, 20));
			}
			const { ws, messages } = await connect();
			const text = "stdio chat integration";
			ws.send(JSON.stringify({ type: "send", text }));
			await waitFor(
				() => messages.some((message) => message.type === "message_done" || message.type === "error"),
				10_000,
			);
			expect(messages.filter((message) => message.type === "error")).toEqual([]);
			const done = messages.find((message) => message.type === "message_done");
			expect(done).toMatchObject({ type: "message_done", text: `Echo: ${text}` });
			if (done?.type !== "message_done") throw new Error("No completed assistant message");
			const deltas = messages.filter((message) => message.type === "message_delta");
			expect(deltas.length).toBeGreaterThan(0);
			expect(deltas.map((message) => message.delta).join("")).toBe(done.text);
			for (const delta of deltas) {
				expect(delta.messageId).toBe(done.messageId);
				expect(messages.indexOf(delta)).toBeLessThan(messages.indexOf(done));
			}
			expect(messages).toContainEqual(expect.objectContaining({ type: "user_message", text }));
			expect(messages).toContainEqual(expect.objectContaining({ type: "agent_state", state: "thinking" }));
			await waitFor(() =>
				messages.some((message) => message.type === "agent_state" && message.state === "idle"),
			);
			const wsClosed = new Promise<void>((resolve) => ws.once("close", () => resolve()));
			ws.close();
			await wsClosed;
			const reloaded = await connect();
			reloaded.ws.send(JSON.stringify({ type: "get_history" }));
			const history = await waitFor(() => reloaded.messages.find((message) => message.type === "history"));
			expect(history.messages).toHaveLength(2);
			expect(history.messages).toEqual(
				expect.arrayContaining([
					expect.objectContaining({ role: "user", text }),
					expect.objectContaining({ role: "assistant", text: `Echo: ${text}` }),
				]),
			);
			child.stdin.write(`${JSON.stringify({ kind: "request", id: 71, method: "computer_unregister" })}\n`);
			const answer = await waitFor(() =>
				frames.find((frame) => frame.kind === "response" && frame.id === 71),
			);
			expect(answer).toEqual({ kind: "response", id: 71, result: {} });
			expect(frames.some((frame) => frame.kind === "request" && frame.method === "secret_get")).toBe(true);
			child.stdin.end();
			await waitFor(() => closed, 15_000);
			expect(exitCode).toBe(0);
			expect(reloaded.ws.readyState).toBe(WebSocket.CLOSED);
			expect(invalidLines).toEqual([]);
			expect(pending).toBe("");
			expect(stderr).toContain("the desktop app's channel closed; stopping the assistant");
		} catch (error) {
			throw new Error(`stdio chat failed (exit=${exitCode}, spawn=${spawnError?.message}); ${stderr}`, {
				cause: error,
			});
		} finally {
			for (const ws of sockets) ws.terminate();
			child.stdin.end();
			if (!closed) child.kill("SIGTERM");
			await exited;
		}
	},
);
