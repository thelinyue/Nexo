export type AgentRelease = { version: string | null; release_url: string | null };

/** 只比较可确认的正式数字版本；缺失、开发版或异常上报不能被误判为需要更新。 */
export function deviceNeedsUpdate(current: string | null | undefined, latest: string | null | undefined): boolean {
  const parse = (value?: string | null) => {
    if (!value || !/^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value)) return null;
    const parts = value.replace(/^v/, "").split(".").map(Number);
    return parts.every(Number.isSafeInteger) ? parts : null;
  };
  const installed = parse(current); const target = parse(latest);
  if (!installed || !target) return false;
  for (let i = 0; i < 3; i++) if (installed[i] !== target[i]) return installed[i] < target[i];
  return false;
}

export const deviceVersionText = (version?: string | null) => !version ? "版本待上报" : /^v?\d+\.\d+\.\d+(?:[-+].+)?$/.test(version) ? `v${version.replace(/^v/, "")}` : version;
