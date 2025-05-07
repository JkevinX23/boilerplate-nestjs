import { Controller, Get, VERSION_NEUTRAL } from '@nestjs/common';
import {
  HealthCheckService,
  HttpHealthIndicator,
  TypeOrmHealthIndicator,
  MemoryHealthIndicator,
  HealthCheck,
} from '@nestjs/terminus';
import { RedisHealthIndicator } from './redis.health';

@Controller({
  path: 'health',
  version: VERSION_NEUTRAL,
})
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private http: HttpHealthIndicator,
    private db: TypeOrmHealthIndicator,
    private memory: MemoryHealthIndicator,
    private redis: RedisHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      () => this.http.pingCheck('external-service', 'https://google.com'),
      () => this.db.pingCheck('database'),
      () => this.memory.checkHeap('memory_heap', 250 * 1024 * 1024), // 250 MB
      () => this.memory.checkRSS('memory_rss', 250 * 1024 * 1024), // 250 MB
      () => this.redis.check('redis_cache'),
    ]);
  }
}
