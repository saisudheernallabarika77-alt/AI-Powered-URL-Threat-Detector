import { COOKIE_NAME } from "@shared/const";
import { z } from "zod";
import { getSessionCookieOptions } from "./_core/cookies";
import { ENV } from "./_core/env";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";

const VIRUSTOTAL_ENDPOINT = "https://www.virustotal.com/api/v3";

type VirusTotalPayload = {
  data?: {
    id?: string;
    type?: string;
    attributes?: {
      status?: string;
      stats?: Record<string, number>;
      reputation?: number;
      permalink?: string;
    };
    links?: { self?: string };
  };
};

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function virusTotalRequest(path: string, init: RequestInit = {}) {
  if (!ENV.virusTotalApiKey) throw new Error("VirusTotal API key is not configured");
  return fetch(`${VIRUSTOTAL_ENDPOINT}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      "x-apikey": ENV.virusTotalApiKey,
      ...(init.headers ?? {}),
    },
  });
}

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),

  virustotal: router({
    checkUrl: publicProcedure
      .input(z.object({ url: z.string().url().max(2048) }))
      .mutation(async ({ input }) => {
        if (!ENV.virusTotalApiKey) {
          return {
            available: false,
            status: "unavailable",
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            reputation: null,
            analysisId: null,
            permalink: null,
          };
        }

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 20_000);
        try {
          const form = new URLSearchParams({ url: input.url });
          const submitResponse = await virusTotalRequest("/urls", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: form.toString(),
            signal: controller.signal,
          });
          if (!submitResponse.ok) throw new Error(`VirusTotal submit HTTP ${submitResponse.status}`);

          const submitted = (await submitResponse.json()) as VirusTotalPayload;
          const analysisId = submitted.data?.id;
          if (!analysisId) throw new Error("VirusTotal did not return an analysis ID");

          let analysis: VirusTotalPayload["data"] | undefined;
          for (let attempt = 0; attempt < 4; attempt += 1) {
            const analysisResponse = await virusTotalRequest(`/analyses/${encodeURIComponent(analysisId)}`, {
              signal: controller.signal,
            });
            if (!analysisResponse.ok) throw new Error(`VirusTotal analysis HTTP ${analysisResponse.status}`);
            const payload = (await analysisResponse.json()) as VirusTotalPayload;
            analysis = payload.data;
            if (analysis?.attributes?.status === "completed") break;
            await wait(700);
          }

          const stats = analysis?.attributes?.stats ?? {};
          return {
            available: true,
            status: analysis?.attributes?.status ?? "queued",
            malicious: Number(stats.malicious ?? 0),
            suspicious: Number(stats.suspicious ?? 0),
            harmless: Number(stats.harmless ?? 0),
            undetected: Number(stats.undetected ?? 0),
            reputation: analysis?.attributes?.reputation ?? null,
            analysisId,
            permalink: analysis?.attributes?.permalink ?? null,
          };
        } catch {
          return {
            available: false,
            status: "unavailable",
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            reputation: null,
            analysisId: null,
            permalink: null,
          };
        } finally {
          clearTimeout(timeout);
        }
      }),
  }),
});

export type AppRouter = typeof appRouter;
