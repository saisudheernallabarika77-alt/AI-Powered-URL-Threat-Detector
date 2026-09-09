import { describe, expect, it } from "vitest";

describe("VirusTotal credentials", () => {
  it("authenticates against the lightweight current-user endpoint", async () => {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      throw new Error("VIRUSTOTAL_API_KEY is not available to the test environment");
    }

    const response = await fetch("https://www.virustotal.com/api/v3/users/current", {
      headers: { "x-apikey": apiKey },
    });

    expect(response.status).toBe(200);
    const payload = (await response.json()) as { data?: { type?: string } };
    expect(payload.data?.type).toBe("user");
  }, 20_000);
});

