import { Injectable, Inject } from '@nestjs/common';
import { HealthIndicatorResult } from '@nestjs/terminus';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache as CacheManagerCacheInterface } from 'cache-manager';
import { parseRedisInfo } from './aux.helth';

interface RedisClient {
  ping: () => Promise<string>;
  info: (section?: string) => Promise<string>;
}

interface CustomRedisStore {
  getClient: () => RedisClient;
}

interface CacheWithRedisStore extends CacheManagerCacheInterface {
  store: CustomRedisStore;
}

@Injectable()
export class RedisHealthIndicator {
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: CacheWithRedisStore,
    private readonly defaultMaxMemoryRSS: number = 250 * 1024 * 1024, // 250 MB
  ) {}

  async check(
    key: string,
    maxMemoryRSS?: number,
  ): Promise<HealthIndicatorResult> {
    const memoryThreshold = maxMemoryRSS || this.defaultMaxMemoryRSS;
    let client: RedisClient;

    try {
      const store = this.cacheManager.store;

      if (!store || typeof store.getClient !== 'function') {
        return {
          [key]: {
            status: 'down',
            message:
              'Cliente Redis não disponível ou getClient não é uma função.',
          },
        };
      }

      client = store.getClient();
      if (!client) {
        return {
          [key]: {
            status: 'down',
            message: 'Falha ao obter o cliente Redis do store.',
          },
        };
      }

      await client.ping();

      if (typeof client.info !== 'function') {
        console.warn('O cliente Redis não suporta a função info.');
        return {
          [key]: {
            status: 'up',
            ping_status: 'up',
            memory_check_skipped: 'client.info not available',
          },
        };
      }

      const infoString = await client.info('memory');
      const memoryInfo = parseRedisInfo(infoString);

      const usedMemoryRss = parseInt(memoryInfo.used_memory_rss, 10);
      const usedMemoryRssHuman = memoryInfo.used_memory_rss_human;
      const usedMemory = parseInt(memoryInfo.used_memory, 10);
      const usedMemoryHuman = memoryInfo.used_memory_human;
      const maxMemoryConfig =
        memoryInfo.maxmemory === '0' ? 'unlimited' : memoryInfo.maxmemory_human;

      if (isNaN(usedMemoryRss)) {
        const errorResult = {
          [key]: {
            status: 'down' as const,
            message: 'Falha ao parsear used_memory_rss do Redis INFO.',
            ping_status: 'up',
            raw_memory_info: memoryInfo,
          },
        };
        return errorResult;
      }

      const isMemoryHealthy = usedMemoryRss < memoryThreshold;

      const details = {
        ping_status: 'up',
        used_memory: usedMemoryHuman,
        used_memory_bytes: usedMemory,
        used_memory_rss: usedMemoryRssHuman,
        used_memory_rss_bytes: usedMemoryRss,
        maxmemory_configured: maxMemoryConfig,
        rss_threshold_bytes: memoryThreshold,
        memory_status: isMemoryHealthy ? 'healthy' : 'unhealthy_rss_too_high',
      };

      if (!isMemoryHealthy) {
        const errorResult = {
          [key]: { status: 'down' as const, ...details },
        };
        return errorResult;
      }

      return { [key]: { status: 'up', ...details } };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'O ping para o Redis falhou.';
      return { [key]: { status: 'down', message: errorMessage } };
    }
  }
}
