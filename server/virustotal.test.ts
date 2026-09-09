import { afterEach, describe, expect, it, vi } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

const ctx: TrpcContext = {
  user: null,
  req: {} as TrpcContext["req"],
  res: {} as TrpcContext["res"],
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("virustotal.checkUrl", () => {
  it("submits a URL and returns malicious vendor counts", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: { id: "analysis-123" } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        data: { type: "analysis", attributes: { status: "completed", stats: { malicious: 4, suspicious: 2, harmless: 10, undetected: 70 }, reputation: -20 } },
      }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await appRouter.createCaller(ctx).virustotal.checkUrl({
      url: "https://example.com/login",
    });

    expect(result).toMatchObject({
      available: true,
      status: "completed",
      malicious: 4,
      suspicious: 2,
      harmless: 10,
      undetected: 70,
      reputation: -20,
      analysisId: "analysis-123",
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://www.virustotal.com/api/v3/urls");
  });

  it("returns a completed clean verdict when no vendors flag the URL", async () => {
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: { id: "analysis-clean" } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        data: { type: "analysis", attributes: { status: "completed", stats: { malicious: 0, suspicious: 0, harmless: 42, undetected: 30 } } },
      }), { status: 200 })));

    const result = await appRouter.createCaller(ctx).virustotal.checkUrl({ url: "https://example.com" });

    expect(result).toMatchObject({ available: true, status: "completed", malicious: 0, suspicious: 0, harmless: 42 });
  });

  it("returns an unavailable result when VirusTotal rejects the request", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("forbidden", { status: 403 })));

    const result = await appRouter.createCaller(ctx).virustotal.checkUrl({ url: "https://example.com" });

    expect(result).toMatchObject({
      available: false,
      status: "unavailable",
      malicious: 0,
      suspicious: 0,
    });
  });
});

