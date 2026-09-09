import { useState } from "react";
import type { FormEvent } from "react";
import { trpc } from "@/lib/trpc";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Bug,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Eye,
  Info,
  Link2,
  LockKeyhole,
  Network,
  Radar,
  ScanLine,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  X,
  XCircle,
  Zap,
} from "lucide-react";

type ScanStatus = "idle" | "scanning" | "safe" | "danger" | "unknown";

type ScanResult = {
  status: "safe" | "danger" | "unknown";
  score: number;
  label: string;
  attackType: string;
  summary: string;
  purpose: string;
  attack: string;
  indicators: { name: string; value: string; state: "pass" | "flag" }[];
};

const sampleUrls = [
  { label: "Safe demo", value: "https://developer.mozilla.org/en-US/" },
  { label: "Threat demo", value: "http://secure-login-verification.xyz/account" },
];

const threatLibrary = [
  { icon: Target, title: "Credential phishing", text: "Fake login pages that capture passwords, OTPs, or recovery codes." },
  { icon: Bug, title: "Malware delivery", text: "Downloads that can install ransomware, spyware, or other unwanted code." },
  { icon: Network, title: "Redirect chains", text: "Multiple hidden redirects that mask a malicious final destination." },
  { icon: Eye, title: "Tracking & impersonation", text: "Lookalike domains designed to profile or manipulate visitors." },
];

function normaliseUrl(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function isValidHttpUrl(value: string) {
  try {
    const parsed = new URL(value);
    return (parsed.protocol === "http:" || parsed.protocol === "https:") && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

function analyseUrl(value: string): ScanResult {
  const url = normaliseUrl(value);
  const lower = url.toLowerCase();
  const hasHttp = lower.startsWith("http://");
  const hasIpHost = /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i.test(url);
  const hasEncoded = /%[0-9a-f]{2}/i.test(url);
  const suspiciousTld = [".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf"].some((signal) => lower.includes(signal));
  const shortener = ["bit.ly/", "tinyurl.com/", "t.co/", "goo.gl/", "is.gd/", "ow.ly/", "shorturl.at/"].some((signal) => lower.includes(signal));
  const hasQuery = url.includes("?");
  const hasFragment = url.includes("#");

  const attackRules = [
    { label: "CROSS-SITE SCRIPTING (XSS) VIA URL", signals: ["<script", "%3cscript", "javascript:", "onerror=", "onload=", "alert(", "document.cookie"], purpose: "The URL contains script-like input that may execute in a vulnerable page context.", attack: "XSS can run attacker-controlled JavaScript, alter page content, or attempt to read browser data." },
    { label: "SQL INJECTION VIA URL", signals: ["union+select", "union%20select", "union select", "or+1=1", "or%201%3d1", "or '1'='1", "' or '1'='1", "'--", "%27--", "information_schema", "sleep(", "waitfor+delay", "select+from"], purpose: "The URL contains database query syntax that may be probing an unsafe server-side parameter.", attack: "SQL injection can expose, change, or delete database records when input is not safely handled." },
    { label: "MALICIOUS FILE DOWNLOAD ATTACK", signals: [".exe", ".msi", ".apk", ".scr", ".bat", ".cmd", ".dmg", ".zip", ".rar", "/download", "download?", "payload"], purpose: "The URL appears to point toward a potentially dangerous executable or archive download.", attack: "Malicious downloads can install spyware, ransomware, trojans, or other unwanted software." },
    { label: "DRIVE-BY DOWNLOAD ATTACK", signals: ["drive-by", "autodownload", "auto-download", "silent-download", "exploit-kit", "browser-update", "flash-update", "codec-update"], purpose: "The URL may be designed to trigger an unwanted download or exploit during a visit.", attack: "Drive-by attacks abuse browser or plugin weaknesses to deliver malware without a clear user action." },
    { label: "SESSION / TOKEN THEFT VIA URL", signals: ["session=", "session_token=", "sessionid=", "sessid=", "token=", "auth_token=", "access_token=", "jwt=", "sid=", "phpsessid"], purpose: "The URL exposes a session identifier, access token, or authentication value in its query or fragment.", attack: "Anyone who obtains a live token may impersonate the account until the session is revoked or expires." },
    { label: "OPEN REDIRECT ATTACK", signals: ["redirect=", "redirect_url=", "redirect_uri=", "return_url=", "returnto=", "next=", "continue=", "url=http", "target=http", "dest=http"], purpose: "The URL contains a redirect parameter that may send visitors to an untrusted destination.", attack: "Open redirects are commonly used to hide a malicious final page behind a trusted domain." },
    { label: "URL OBFUSCATION ATTACK", signals: ["%25", "%2f", "%5c", "%3a", "%2e%2e", "%6c%6f%67%69%6e", "\\x", "base64", "atob(", "0x", "0000", "user:pass@", "@http"], purpose: "The URL uses encoded, nested, or unusual formatting to make its destination or payload harder to inspect.", attack: "Obfuscation can conceal phishing destinations, scripts, redirects, or malicious parameters from users and filters." },
    { label: "HOMOGRAPH ATTACK", signals: ["xn--", "аррle", "раypal", "micrоsoft", "gооgle", "ạ", "ｅ", "ο"], purpose: "The domain may use lookalike Unicode characters to visually imitate a trusted brand.", attack: "Homograph domains trick users into believing they are visiting a legitimate website." },
    { label: "TYPOSQUATTING ATTACK", signals: ["paypa1", "paypol", "pay-pal", "faceb00k", "facebok", "g00gle", "gooogle", "micros0ft", "amaz0n", "netf1ix", "secure-login-verification"], purpose: "The domain resembles a well-known brand but appears intentionally misspelled or altered.", attack: "Typosquatting captures mistyped traffic and may imitate a brand to steal data or distribute malware." },
    { label: "BANKING PHISHING ATTACK", signals: ["bank-login", "banking-login", "netbanking", "online-banking", "secure-bank", "icici", "hdfc", "sbi-login", "chase-login", "paypal-login", "verify-card", "upi", "credit-card"], purpose: "The URL appears to imitate a banking, payment, card, or UPI verification flow.", attack: "Banking phishing targets card numbers, PINs, OTPs, UPI credentials, and online banking passwords." },
    { label: "CREDENTIAL HARVESTING ATTACK", signals: ["secure-login", "verify-account", "password-reset", "signin", "sign-in", "login", "credential", "account-verification", "otp", "unlock-account", "wallet-connect"], purpose: "The URL likely leads to a fake sign-in or verification form designed to collect credentials.", attack: "Credential harvesting steals usernames, passwords, OTPs, recovery codes, or wallet secrets." },
    { label: "SCAM / FRAUD URL ATTACK", signals: ["free-gift", "claim-prize", "winner", "lottery", "refund", "cashback", "giveaway", "urgent-payment", "investment", "crypto-profit", "double-your", "job-offer", "act-now", "fraud", "scam", "phishing", "verify-now", "limited-time", "loan", "kyc", "pan-card", "earn-money", "bonus", "casino", "betting"], purpose: "The URL uses a reward, refund, investment, job, or urgency theme commonly seen in online scams.", attack: "Scam pages pressure users to pay money, share personal information, or send cryptocurrency." },
    { label: "MALICIOUS SHORT URL ATTACK", signals: ["bit.ly/", "tinyurl.com/", "t.co/", "goo.gl/", "is.gd/", "ow.ly/", "shorturl.at/"], purpose: "The link uses a URL shortener that hides the final destination from the visitor.", attack: "Attackers use short links to conceal phishing pages, malware downloads, and redirect chains." },
    { label: "MALWARE URL ATTACK", signals: ["malware", "trojan", "ransomware", "spyware", "virus", "crack", "keygen", "payload", ".exe", ".apk"], purpose: "The URL contains language or file patterns associated with malicious software delivery.", attack: "Malware can steal data, monitor activity, encrypt files, or damage the device." },
    { label: "PHISHING URL ATTACK", signals: ["secure-login-verification", "paypal-account-verify", "verify-account", "password-reset", "account-alert", "confirm-identity", "login-required", "suspicious-login", "fake-login"], purpose: "The URL likely impersonates a trusted service and asks the visitor to take an urgent account action.", attack: "Phishing uses fake messages and pages to steal personal information, credentials, or payment details." },
  ];
  let decoded = lower;
  try {
    decoded = `${lower} ${decodeURIComponent(lower)}`;
  } catch {
    // Keep the encoded URL if a malformed escape sequence is present.
  }
  const signalText = decoded.replace(/\s+/g, " ");
  const priority = [
    "CROSS-SITE SCRIPTING (XSS) VIA URL",
    "SQL INJECTION VIA URL",
    "DRIVE-BY DOWNLOAD ATTACK",
    "MALICIOUS FILE DOWNLOAD ATTACK",
    "SESSION / TOKEN THEFT VIA URL",
    "OPEN REDIRECT ATTACK",
    "HOMOGRAPH ATTACK",
    "TYPOSQUATTING ATTACK",
    "BANKING PHISHING ATTACK",
    "CREDENTIAL HARVESTING ATTACK",
    "SCAM / FRAUD URL ATTACK",
    "MALICIOUS SHORT URL ATTACK",
    "MALWARE URL ATTACK",
    "PHISHING URL ATTACK",
    "URL OBFUSCATION ATTACK",
  ];
  const matchedRule = priority
    .map((label) => attackRules.find((rule) => rule.label === label && rule.signals.some((signal) => signalText.includes(signal))))
    .find(Boolean);
  const danger = Boolean(matchedRule) || hasHttp || hasIpHost || suspiciousTld || (shortener && hasQuery) || (hasEncoded && hasFragment);

  if (danger) {
    const fallbackRule = { label: "SUSPICIOUS URL ATTACK", purpose: "The URL contains unusual security signals and should be treated cautiously until independently verified.", attack: "Suspicious links can redirect to phishing pages, malware, scams, or other harmful content." };
    const rule = matchedRule ?? fallbackRule;
    return {
      status: "danger",
      score: hasIpHost || suspiciousTld || matchedRule ? 92 : 78,
      label: "High risk detected",
      attackType: rule.label,
      summary: `This URL matches signals associated with ${rule.label.toLowerCase()}.`,
      purpose: rule.purpose,
      attack: rule.attack,
      indicators: [
        { name: "Domain reputation", value: "Suspicious pattern", state: "flag" },
        { name: "Transport security", value: hasHttp ? "No HTTPS" : "Review needed", state: hasHttp ? "flag" : "pass" },
        { name: "URL structure", value: hasIpHost ? "Raw IP host" : hasEncoded ? "Encoded params" : "Lookalike wording", state: "flag" },
        { name: "Known attack signals", value: "Matched", state: "flag" },
      ],
    };
  }

  return {
    status: "safe",
    score: 96,
    label: "URL appears safe",
    attackType: "NO ATTACK DETECTED",
    summary: "No obvious malicious signals were found in this quick client-side analysis.",
    purpose: "Likely a standard public website or documentation resource. Always verify the domain before sharing sensitive data.",
    attack: "No immediate indicators. Stay alert for unexpected downloads, popups, or login requests.",
    indicators: [
      { name: "Domain reputation", value: "No obvious flags", state: "pass" },
      { name: "Transport security", value: "HTTPS enabled", state: "pass" },
      { name: "URL structure", value: "Looks normal", state: "pass" },
      { name: "Known attack signals", value: "Not detected", state: "pass" },
    ],
  };
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [showLibrary, setShowLibrary] = useState(false);
  const virusTotalCheck = trpc.virustotal.checkUrl.useMutation();

  const handleScan = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!url.trim()) return;
    setStatus("scanning");
    setResult(null);
    const normalized = normaliseUrl(url);

    if (!isValidHttpUrl(normalized)) {
      const invalidResult: ScanResult = {
        status: "unknown",
        score: 0,
        label: "Invalid URL format",
        attackType: "URL VALIDATION ERROR",
        summary: "Please enter a complete web address before starting the scan.",
        purpose: "The scanner accepts HTTP or HTTPS URLs such as https://example.com.",
        attack: "An incomplete or malformed address cannot be checked reliably. No request was sent to the threat-intelligence service.",
        indicators: [
          { name: "URL format", value: "Invalid", state: "flag" },
          { name: "Threat lookup", value: "Not started", state: "pass" },
        ],
      };
      setResult(invalidResult);
      setStatus(invalidResult.status);
      return;
    }

    const localResult = analyseUrl(normalized);

    try {
      const reputation = await virusTotalCheck.mutateAsync({ url: normalized });
      const providerFlagged = reputation.malicious > 0 || reputation.suspicious > 0;
      const providerDetections = reputation.malicious + reputation.suspicious;

      if (providerFlagged && localResult.status === "danger") {
        const next: ScanResult = {
          ...localResult,
          score: reputation.malicious > 0 ? 99 : Math.max(localResult.score, 94),
          summary: `${localResult.summary} VirusTotal detected ${providerDetections} malicious or suspicious security vendor signal${providerDetections === 1 ? "" : "s"}.`,
          indicators: [
            { name: "VirusTotal detections", value: `${reputation.malicious} malicious · ${reputation.suspicious} suspicious`, state: "flag" },
            ...localResult.indicators,
          ],
        };
        setResult(next);
        setStatus(next.status);
        return;
      }

      if (providerFlagged) {
        const next: ScanResult = {
          ...localResult,
          status: "danger",
          score: reputation.malicious > 0 ? 99 : 92,
          label: reputation.malicious > 0 ? "VirusTotal flagged this URL" : "Suspicious vendor signals found",
          attackType: reputation.malicious > 0 ? "MALICIOUS URL ATTACK" : "SUSPICIOUS URL ATTACK",
          summary: `VirusTotal received ${reputation.malicious} malicious and ${reputation.suspicious} suspicious vendor signal${providerDetections === 1 ? "" : "s"}.`,
          purpose: "The URL was flagged by VirusTotal security vendors and should not be opened or trusted without independent verification.",
          attack: "Malicious URLs may deliver phishing pages, malware, scams, redirects, or other harmful content.",
          indicators: [
            { name: "VirusTotal detections", value: `${reputation.malicious} malicious · ${reputation.suspicious} suspicious`, state: "flag" },
            ...localResult.indicators,
          ],
        };
        setResult(next);
        setStatus(next.status);
        return;
      }

      if (localResult.status === "danger") {
        const next: ScanResult = {
          ...localResult,
          summary: `${localResult.summary} VirusTotal did not return a malicious vendor signal for this scan.`,
          indicators: [
            { name: "VirusTotal detections", value: reputation.available ? "0 malicious · 0 suspicious" : "Lookup unavailable", state: reputation.available ? "pass" : "flag" },
            ...localResult.indicators,
          ],
        };
        setResult(next);
        setStatus(next.status);
        return;
      }

      if (reputation.available && reputation.status === "completed") {
        const next: ScanResult = {
          ...localResult,
          score: 94,
          label: "No malicious vendors detected",
          summary: `VirusTotal completed its scan with ${reputation.harmless} harmless and ${reputation.undetected} undetected vendor result${reputation.harmless + reputation.undetected === 1 ? "" : "s"}.`,
          purpose: "The URL did not receive a malicious or suspicious vendor verdict in this VirusTotal scan. Still verify unfamiliar domains before sharing sensitive information.",
          attack: "No immediate provider detections were returned. New or private threats may not yet be known to security vendors.",
          indicators: [
            { name: "VirusTotal detections", value: "0 malicious · 0 suspicious", state: "pass" },
            { name: "VirusTotal coverage", value: `${reputation.harmless} harmless · ${reputation.undetected} undetected`, state: "pass" },
            ...localResult.indicators,
          ],
        };
        setResult(next);
        setStatus(next.status);
        return;
      }

      const next: ScanResult = {
        ...localResult,
        status: "unknown",
        score: 50,
        label: "Scan still processing",
        attackType: "UNKNOWN — NOT CONFIRMED SAFE",
        summary: "VirusTotal accepted the URL, but its vendor analysis is still processing. This is not a Safe verdict.",
        purpose: "The URL needs a completed multi-vendor analysis before its reputation can be interpreted.",
        attack: "Do not open or share the URL while analysis is pending. Retry shortly for the completed vendor result.",
        indicators: [
          { name: "VirusTotal status", value: reputation.status, state: "flag" },
          { name: "Known attack signals", value: "Not confirmed", state: "pass" },
          ...localResult.indicators,
        ],
      };
      setResult(next);
      setStatus(next.status);
    } catch {
      if (localResult.status === "danger") {
        setResult({
          ...localResult,
          summary: `${localResult.summary} The VirusTotal lookup was unavailable, so this classification is based on local threat signals.`,
          indicators: [
            { name: "VirusTotal reputation", value: "Lookup unavailable", state: "flag" },
            ...localResult.indicators,
          ],
        });
        setStatus(localResult.status);
        return;
      }
      const next: ScanResult = {
        ...localResult,
        status: "unknown",
        score: 35,
        label: "Unable to confirm reputation",
        attackType: "SCAN UNAVAILABLE",
        summary: "The remote VirusTotal lookup could not be completed, so this URL cannot be classified reliably right now.",
        purpose: "The local pattern check did not find a confirmed category, but the external multi-vendor scan was unavailable.",
        attack: "Do not treat an unavailable scan as safe. Retry the scan or verify the website through a trusted channel.",
        indicators: [
          { name: "VirusTotal reputation", value: "Lookup unavailable", state: "flag" },
          ...localResult.indicators,
        ],
      };
      setResult(next);
      setStatus(next.status);
    }
  };

  const loadExample = (value: string) => {
    setUrl(value);
    setStatus("idle");
    setResult(null);
  };

  const clearScan = () => {
    setUrl("");
    setStatus("idle");
    setResult(null);
  };

  const isDanger = status === "danger";
  const isUnknown = status === "unknown";

  return (
    <div className="min-h-screen overflow-hidden bg-[#0a0b0a] text-slate-100 selection:bg-teal-400/30">
      <div className="cyber-noise" aria-hidden="true" />
      <div className="cyber-orb cyber-orb-left" aria-hidden="true" />
      <div className="cyber-orb cyber-orb-right" aria-hidden="true" />

      <header className="relative z-10 border-b border-white/[0.07] bg-[#0a0b0a]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1240px] items-center justify-between px-5 py-5 lg:px-8">
          <a className="group flex items-center gap-3" href="#top" aria-label="AI Powered URL Detector home">
            <span className="relative flex h-10 w-10 items-center justify-center rounded-xl border border-teal-300/30 bg-teal-300/[0.09] text-teal-300 shadow-[0_0_22px_rgba(34,211,238,0.16)] transition group-hover:border-teal-300/60">
              <ShieldCheck size={20} strokeWidth={2.2} />
              <span className="absolute -right-1 -top-1 h-2 w-2 rounded-full bg-teal-300 shadow-[0_0_10px_#67d9e8]" />
            </span>
            <span>
              <span className="block text-[14px] font-semibold tracking-[0.04em] text-white">AI-Powered URL Detector</span>
              <span className="mt-0.5 block font-mono text-[10px] uppercase tracking-[0.18em] text-slate-500">Threat intelligence console</span>
            </span>
          </a>
          <div className="hidden items-center gap-7 text-[12px] font-medium text-slate-500 md:flex">
            <a className="transition hover:text-teal-200" href="#how-it-works">How it works</a>
            <button className="transition hover:text-teal-200" onClick={() => { setShowLibrary(true); window.setTimeout(() => document.getElementById("threat-library")?.scrollIntoView({ behavior: "smooth" }), 40); }}>Threat library</button>
            <span className="flex items-center gap-2 rounded-full border border-emerald-300/15 bg-emerald-300/[0.05] px-3 py-1.5 text-emerald-300"><span className="h-1.5 w-1.5 rounded-full bg-emerald-300 shadow-[0_0_8px_#7dd3a8]" />Scanner online</span>
          </div>
        </div>
      </header>

      <main id="top" className="relative z-10 mx-auto max-w-[1240px] px-5 pb-20 pt-14 lg:px-8 lg:pt-20">
        <section className="grid items-start gap-12 lg:grid-cols-[minmax(0,1.05fr)_minmax(420px,0.95fr)] lg:gap-20">
          <div className="pt-2">
            <div className="mb-7 inline-flex items-center gap-2 rounded-full border border-teal-300/20 bg-teal-300/[0.06] px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-teal-200">
              <Sparkles size={13} /> AI-assisted threat analysis
            </div>
            <h1 className="max-w-2xl text-[clamp(3.3rem,6vw,5.7rem)] font-semibold leading-[0.94] tracking-[-0.07em] text-white">
              See the threat
              <span className="block bg-gradient-to-r from-teal-200 via-teal-200 to-sky-200 bg-clip-text text-transparent">before you click.</span>
            </h1>
            <p className="mt-7 max-w-xl text-[16px] leading-7 text-slate-400">Paste a URL and let our AI-powered scanner inspect its structure, security signals, and likely intent — in seconds.</p>
            <div className="mt-9 flex flex-wrap items-center gap-5 text-[11px] font-medium text-slate-500">
              <span className="flex items-center gap-2"><Check size={14} className="text-teal-300" /> No account needed</span>
              <span className="flex items-center gap-2"><LockKeyhole size={14} className="text-teal-300" /> URLs are not stored</span>
              <span className="flex items-center gap-2"><Zap size={14} className="text-teal-300" /> Instant results</span>
            </div>
          </div>

          <div className="relative">
            <div className="absolute -inset-4 rounded-[30px] bg-teal-300/[0.04] blur-2xl" />
            <form onSubmit={handleScan} className="scan-card relative rounded-2xl border border-white/[0.12] bg-[#141614]/90 p-5 shadow-[0_24px_100px_rgba(0,0,0,0.42)] backdrop-blur-xl sm:p-6">
              <div className="mb-6 flex items-center justify-between">
                <div className="flex items-center gap-2.5"><span className="flex h-8 w-8 items-center justify-center rounded-lg bg-teal-300/10 text-teal-300"><ScanLine size={16} /></span><span className="text-sm font-semibold text-white">Scan a URL</span></div>
                <span className="font-mono text-[10px] uppercase tracking-[0.17em] text-slate-600">Engine v2.4</span>
              </div>
              <label htmlFor="url-input" className="mb-2 block font-mono text-[10px] uppercase tracking-[0.17em] text-slate-500">Target URL</label>
              <div className="group flex min-h-[56px] items-center gap-3 rounded-xl border border-white/[0.12] bg-[#0a0b0a]/70 px-4 transition focus-within:border-teal-300/60 focus-within:ring-4 focus-within:ring-teal-300/[0.07]">
                <Link2 size={17} className="shrink-0 text-slate-600 transition group-focus-within:text-teal-300" />
                <input id="url-input" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="Paste a URL to inspect..." className="min-w-0 flex-1 bg-transparent text-[14px] text-slate-100 outline-none placeholder:text-slate-600" autoComplete="off" />
                {url && <button type="button" onClick={clearScan} className="text-slate-600 transition hover:text-slate-200" aria-label="Clear URL"><X size={16} /></button>}
              </div>
              <button disabled={!url.trim() || status === "scanning"} type="submit" className="mt-3 flex h-12 w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-teal-300 to-teal-400 text-[13px] font-bold text-[#211b10] shadow-[0_8px_25px_rgba(34,211,238,0.2)] transition hover:brightness-110 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40">
                {status === "scanning" ? <><Activity size={16} className="animate-pulse" /> Running analysis...</> : <><Radar size={16} /> Analyze URL with AI <ArrowUpRight size={15} /></>}
              </button>
              <div className="mt-5 flex items-center justify-between gap-3 border-t border-white/[0.07] pt-4">
                <span className="font-mono text-[10px] uppercase tracking-[0.13em] text-slate-600">Try an example</span>
                <div className="flex gap-2">
                  {sampleUrls.map((sample) => <button key={sample.label} type="button" onClick={() => loadExample(sample.value)} className="rounded-md border border-white/[0.08] px-2.5 py-1.5 text-[10px] font-medium text-slate-500 transition hover:border-teal-300/30 hover:text-teal-200">{sample.label}</button>)}
                </div>
              </div>
            </form>

            {status === "scanning" && <div className="mt-3 overflow-hidden rounded-xl border border-teal-300/20 bg-teal-300/[0.05] px-4 py-3 text-[11px] text-teal-200"><div className="flex items-center gap-2"><span className="h-1.5 w-1.5 animate-ping rounded-full bg-teal-300" /> Checking DNS patterns, redirects, and threat signals...</div><div className="mt-3 h-1 overflow-hidden rounded-full bg-teal-300/10"><div className="scan-progress h-full w-1/2 rounded-full bg-teal-300" /></div></div>}
          </div>
        </section>

        {result && <section className={`result-panel mt-10 overflow-hidden rounded-2xl border ${isDanger ? "border-rose-300/30 bg-rose-300/[0.045]" : isUnknown ? "border-teal-300/30 bg-teal-300/[0.045]" : "border-emerald-300/25 bg-emerald-300/[0.045]"}`} aria-live="polite">
          <div className="flex flex-col gap-8 p-6 sm:p-8 lg:flex-row lg:items-start">
            <div className="flex-1">
              <div className="flex flex-wrap items-center gap-3"><span className={`flex h-11 w-11 items-center justify-center rounded-xl ${isDanger ? "bg-rose-300/15 text-rose-300" : isUnknown ? "bg-teal-300/15 text-teal-300" : "bg-emerald-300/15 text-emerald-300"}`}>{isDanger ? <ShieldAlert size={23} /> : isUnknown ? <AlertTriangle size={23} /> : <CheckCircle2 size={23} />}</span><div><p className={`font-mono text-[10px] uppercase tracking-[0.18em] ${isDanger ? "text-rose-300" : isUnknown ? "text-teal-300" : "text-emerald-300"}`}>{isDanger ? "Action recommended" : isUnknown ? "Verification needed" : "Scan complete"}</p><h2 className="mt-1 text-2xl font-semibold tracking-tight text-white">{result.label}</h2></div></div>
              <p className="mt-5 max-w-2xl text-sm leading-6 text-slate-300">{result.summary}</p>
              <div className="mt-6 flex flex-wrap items-center gap-3"><span className="rounded-full border border-white/[0.1] bg-black/20 px-3 py-1.5 font-mono text-[11px] text-slate-400">{normaliseUrl(url)}</span><span className={`rounded-full px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider ${isDanger ? "bg-rose-300/10 text-rose-200" : "bg-emerald-300/10 text-emerald-200"}`}>{isDanger ? "Do not enter credentials" : "Proceed with care"}</span></div>
              <div className={`mt-5 inline-flex items-center gap-2 rounded-lg border px-3 py-2 ${isDanger ? "border-rose-300/30 bg-rose-300/10" : isUnknown ? "border-teal-300/30 bg-teal-300/10" : "border-emerald-300/25 bg-emerald-300/10"}`}><span className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500">Attack type</span><span className={`font-mono text-xs font-bold tracking-[0.12em] ${isDanger ? "text-rose-200" : isUnknown ? "text-teal-200" : "text-emerald-200"}`}>{result.attackType}</span></div>
            </div>
            <div className="flex w-full shrink-0 items-center gap-5 rounded-xl border border-white/[0.08] bg-[#0a0b0a]/35 p-4 sm:w-auto sm:min-w-[220px] lg:flex-col lg:items-center lg:justify-center lg:px-8 lg:py-6"><div className={`relative flex h-24 w-24 items-center justify-center rounded-full border-4 ${isDanger ? "border-rose-300/70" : isUnknown ? "border-teal-300/70" : "border-emerald-300/70"}`}><div className={`absolute inset-1 rounded-full border ${isDanger ? "border-rose-300/15" : isUnknown ? "border-teal-300/15" : "border-emerald-300/15"}`} /><span className="text-2xl font-semibold text-white">{result.score}</span></div><div><p className="text-center font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500">Confidence score</p><p className={`mt-1 text-center text-xs font-medium ${isDanger ? "text-rose-300" : isUnknown ? "text-teal-300" : "text-emerald-300"}`}>{isDanger ? "Risk is elevated" : isUnknown ? "Not confirmed safe" : "Low risk detected"}</p></div></div>
          </div>
          <div className="grid border-t border-white/[0.08] lg:grid-cols-2">
            <div className="p-6 sm:p-8 lg:border-r lg:border-white/[0.08]"><div className="mb-5 flex items-center gap-2"><Target size={15} className="text-teal-300" /><h3 className="text-sm font-semibold text-white">What this URL is likely for</h3></div><p className="text-sm leading-6 text-slate-400">{result.purpose}</p><div className="mt-6 flex items-start gap-3 rounded-xl border border-white/[0.07] bg-black/15 p-4"><Info size={15} className="mt-0.5 shrink-0 text-slate-500" /><p className="text-xs leading-5 text-slate-500"><span className="font-semibold text-slate-300">Just for knowledge — </span>{result.attack}</p></div></div>
            <div className="p-6 sm:p-8"><div className="mb-5 flex items-center gap-2"><Search size={15} className="text-teal-300" /><h3 className="text-sm font-semibold text-white">Signals inspected</h3></div><div className="space-y-3">{result.indicators.map((indicator, index) => <div key={`${indicator.name}-${index}`} className="flex items-center justify-between gap-4 border-b border-white/[0.06] pb-3 last:border-0 last:pb-0"><span className="text-xs text-slate-500">{indicator.name}</span><span className={`flex items-center gap-1.5 text-right text-xs font-medium ${indicator.state === "flag" ? "text-rose-300" : "text-emerald-300"}`}>{indicator.state === "flag" ? <AlertTriangle size={13} /> : <Check size={13} />}{indicator.value}</span></div>)}</div></div>
          </div>
        </section>}

        <section id="how-it-works" className="mt-24 grid gap-12 lg:grid-cols-[0.78fr_1.22fr] lg:gap-20">
          <div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-teal-300">How it works</p><h2 className="mt-4 max-w-md text-3xl font-semibold leading-tight tracking-[-0.04em] text-white">A clearer answer than “looks suspicious.”</h2><p className="mt-5 max-w-md text-sm leading-6 text-slate-500">Our lightweight analysis turns confusing URL signals into a simple explanation you can act on.</p></div>
          <div className="grid gap-3 sm:grid-cols-3">{[{ n: "01", icon: Link2, title: "Paste", text: "Add the link you received in a message, email, or browser." }, { n: "02", icon: Radar, title: "Inspect", text: "We check structure, transport, redirects, and known attack patterns." }, { n: "03", icon: ShieldCheck, title: "Understand", text: "Get a risk signal, likely purpose, and the attack type to watch for." }].map((step) => <div key={step.n} className="group rounded-xl border border-white/[0.08] bg-white/[0.025] p-5 transition hover:-translate-y-1 hover:border-teal-300/25 hover:bg-teal-300/[0.04]"><div className="flex items-center justify-between"><span className="font-mono text-[10px] text-teal-300/70">{step.n}</span><step.icon size={17} className="text-slate-600 transition group-hover:text-teal-300" /></div><h3 className="mt-10 text-sm font-semibold text-white">{step.title}</h3><p className="mt-2 text-xs leading-5 text-slate-500">{step.text}</p></div>)}</div>
        </section>

        {showLibrary && <section id="threat-library" className="mt-24 border-t border-white/[0.07] pt-10"><div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end"><div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-teal-300">Threat library</p><h2 className="mt-3 text-2xl font-semibold tracking-tight text-white">Know what a dangerous link can do.</h2></div><button onClick={() => setShowLibrary(false)} className="flex items-center gap-2 self-start rounded-lg border border-white/[0.1] px-3 py-2 text-xs text-slate-400 transition hover:border-white/20 hover:text-white"><X size={14} /> Close library</button></div><div className="mt-7 grid gap-3 md:grid-cols-2 lg:grid-cols-4">{threatLibrary.map((item) => <div key={item.title} className="rounded-xl border border-white/[0.08] bg-[#141614]/65 p-5"><item.icon size={18} className="text-rose-300" /><h3 className="mt-5 text-sm font-semibold text-white">{item.title}</h3><p className="mt-2 text-xs leading-5 text-slate-500">{item.text}</p></div>)}</div></section>}
      </main>

      <footer className="relative z-10 border-t border-white/[0.07] bg-[#0a0b0a]/70"><div className="mx-auto flex max-w-[1240px] flex-col gap-3 px-5 py-7 text-[11px] text-slate-600 sm:flex-row sm:items-center sm:justify-between lg:px-8"><p className="flex items-center gap-2"><ShieldCheck size={14} className="text-teal-300/70" /> Built for safer clicks on the open web.</p><p className="flex items-center gap-2"><Clock3 size={13} /> Educational scanner · Not a replacement for enterprise security tools</p></div></footer>
    </div>
  );
}
