export function parseRedisInfo(infoString: string): Record<string, string> {
  const lines = infoString.split('\r\n');
  const info: Record<string, string> = {};
  for (const line of lines) {
    if (line && !line.startsWith('#')) {
      const parts = line.split(':');
      if (parts.length === 2) {
        info[parts[0]] = parts[1];
      }
    }
  }
  return info;
}
