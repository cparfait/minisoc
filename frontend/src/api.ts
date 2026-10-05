export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

type Options = { method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE"; body?: unknown };

/** Appel de l'API. L'en-tête X-MiniSOC protège les requêtes modifiantes contre le CSRF. */
export async function api<T>(path: string, { method = "GET", body }: Options = {}): Promise<T> {
  const headers: Record<string, string> = { "X-MiniSOC": "1", Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && !path.startsWith("/auth/login")) {
    window.dispatchEvent(new Event("minisoc:unauthorized"));
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch {
      /* réponse non JSON */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export function query(params: Record<string, string | number | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export type AIEvent =
  | { type: "start"; pseudonymized: boolean; provider: string }
  | { type: "text"; text: string }
  | { type: "notice"; text: string }
  | { type: "done"; model: string; input_tokens: number; output_tokens: number }
  | { type: "error"; message: string };

/** Requête à l'assistant IA : réponse diffusée en continu (Server-Sent Events sur POST). */
export async function streamAI(path: string, body: unknown, onEvent: (e: AIEvent) => void, signal?: AbortSignal) {
  const res = await fetch(`/api${path}`, {
    method: "POST",
    headers: { "X-MiniSOC": "1", "Content-Type": "application/json", Accept: "text/event-stream" },
    credentials: "same-origin",
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok || !res.body) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch {
      /* réponse non JSON */
    }
    if (res.status === 401) window.dispatchEvent(new Event("minisoc:unauthorized"));
    throw new ApiError(res.status, detail);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let index;
    while ((index = buffer.indexOf("\n\n")) >= 0) {
      const frame = buffer.slice(0, index);
      buffer = buffer.slice(index + 2);
      const data = frame.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).join("\n");
      if (data) onEvent(JSON.parse(data) as AIEvent);
    }
  }
}
