/** 跳转沿用本地目标，但浏览器不能使用 Agent 的回环地址或主机名，必须是明确的私网 IP。 */
export function isLanRedirectAddress(value: string): boolean {
  if (/[\u0000-\u001f\u007f]/.test(value)) return false;
  const input = value.trim();
  const address = input.startsWith("[") && input.endsWith("]") ? input.slice(1, -1) : input;
  try {
    if (address.includes(":")) {
      if (!/^[0-9a-f:.]+$/i.test(address)) return false;
      return /^\[f[cd][0-9a-f]{2}:/i.test(new URL(`http://[${address}]`).hostname);
    }
    // 排除 URL 解析器接受的整数、十六进制、八进制及缩写 IPv4，保持与服务端 IP 解析一致。
    if (address !== input || !/^\d+\.\d+\.\d+\.\d+$/.test(address) || new URL(`http://${address}`).hostname !== address) return false;
    const [first, second] = address.split(".").map(Number);
    return first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168);
  } catch { return false; }
}
