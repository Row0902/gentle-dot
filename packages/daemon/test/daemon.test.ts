import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AppChannel } from "../src/app-channel.ts";
import { type DotDaemon, startDaemon } from "../src/daemon.ts";
import { fakeApp } from "./fake-app.ts";
import { FAKE_AGENT, tempDir, waitFor } from "./helpers.ts";

describe("daemon app channel ownership", () => {
	it.each([false, true])("accepts an already constructed channel: %s", async (constructed) => {
		const peer = fakeApp();
		const channel = constructed ? new AppChannel(peer.daemonEnd) : undefined;
		const initialHandler = channel?.handler;
		const dataDir = tempDir();
		let daemon: DotDaemon | undefined;
		try {
			daemon = await startDaemon({
				port: 0,
				host: "127.0.0.1",
				dataDir,
				workspace: join(dataDir, "workspace"),
				uiDir: dataDir,
				agentCommand: process.execPath,
				agentArgs: [FAKE_AGENT],
				appChannel: channel ?? peer.daemonEnd,
			});
			// Installing the daemon handler on this instance proves it was not re-wrapped.
			if (channel) expect(channel.handler).not.toBe(initialHandler);
			expect(await peer.request("computer_unregister")).toEqual({});
			let closed = false;
			void daemon.closed.then(() => {
				closed = true;
			});
			peer.close();
			await waitFor(() => closed, 15_000);
		} finally {
			await daemon?.close();
			channel?.close();
			peer.close();
		}
	});
});
