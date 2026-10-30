import { ScanError, assertPublicHost } from "@/lib/validate";

export const MAX_REDIRECT_HOPS = 5;

export type RedirectChainStatus =
  | "no_redirect"
  | "http_upgraded"
  | "clean_secure"
  | "insecure_start"
  | "invalid_first_upgrade"
  | "downgrade_detected"
  | "max_hops_exceeded"
  | "invalid_redirect";

/** Deliberately URL-free evidence: hosts and paths are used only in memory. */
export interface RedirectHop {
  hopIndex: number;
  statusCode: number;
  protocol: "http" | "https";
  hostChangedFromPrevious: boolean;
}

export interface RedirectEvidence {
  status: RedirectChainStatus;
  secure: boolean;
  hops: RedirectHop[];
}

export type RedirectResponse = Response & { finalUrl: URL };
export type ManualFetch = (url: URL, timeoutMs: number) => Promise<Response>;
export type PublicTargetValidator = (url: URL) => Promise<void>;

const isRedirect = (status: number) => status >= 300 && status < 400;

async function networkFetch(url: URL, timeoutMs: number): Promise<Response> {
  return fetch(url, {
    method: "GET",
    redirect: "manual",
    cache: "no-store",
    signal: AbortSignal.timeout(timeoutMs),
    headers: { "User-Agent": "DevSecGuard/1.0 (security audit)" },
  });
}

/**
 * Fetches each redirect explicitly. Every next target is validated before it can
 * be requested, so a public target cannot redirect the scanner to private space.
 */
export async function verifyRedirectChain(
  initialUrl: URL,
  options: { timeoutMs?: number; fetcher?: ManualFetch; validateTarget?: PublicTargetValidator } = {},
): Promise<{ response: RedirectResponse; evidence: RedirectEvidence }> {
  const timeoutMs = options.timeoutMs ?? 8000;
  const fetcher = options.fetcher ?? networkFetch;
  const validateTarget = options.validateTarget ?? assertPublicHost;
  const hops: RedirectHop[] = [];
  let current = new URL(initialUrl);
  let previous: URL | null = null;
  let sawRedirect = false;

  for (let index = 1; index <= MAX_REDIRECT_HOPS; index++) {
    await validateTarget(current);
    const response = await fetcher(current, timeoutMs);
    const protocol = current.protocol === "https:" ? "https" : "http";
    hops.push({
      hopIndex: index,
      statusCode: response.status,
      protocol,
      hostChangedFromPrevious: previous ? previous.hostname !== current.hostname : false,
    });

    const location = response.headers.get("location");
    if (!isRedirect(response.status)) {
      const hadDowngrade = hops.some((hop, hopIndex) => hopIndex > 0 && hops[hopIndex - 1].protocol === "https" && hop.protocol === "http");
      const firstHop = hops[0];
      const firstUpgradeIsSameHost =
        initialUrl.protocol === "http:" &&
        hops.length >= 2 &&
        firstHop.protocol === "http" &&
        hops[1].protocol === "https" &&
        !hops[1].hostChangedFromPrevious;

      const status: RedirectChainStatus = hadDowngrade
        ? "downgrade_detected"
        : initialUrl.protocol === "http:" && !sawRedirect
          ? "insecure_start"
          : initialUrl.protocol === "http:" && !firstUpgradeIsSameHost
            ? "invalid_first_upgrade"
            : initialUrl.protocol === "http:"
              ? "http_upgraded"
              : sawRedirect
                ? "clean_secure"
                : "no_redirect";
      return {
        response: Object.assign(response, { finalUrl: current }),
        evidence: { status, secure: status === "no_redirect" || status === "http_upgraded" || status === "clean_secure", hops },
      };
    }

    if (!location) {
      await response.body?.cancel();
      return {
        response: Object.assign(response, { finalUrl: current }),
        evidence: { status: "invalid_redirect", secure: false, hops },
      };
    }
    if (index === MAX_REDIRECT_HOPS) {
      await response.body?.cancel();
      throw new ScanError("Too many redirects.", 502);
    }

    const next = new URL(location, current);
    // Validate the redirect target before the next network request, not afterward.
    await validateTarget(next);
    await response.body?.cancel();
    previous = current;
    current = next;
    sawRedirect = true;
  }

  throw new ScanError("Too many redirects.", 502);
}
