import { ConsoleLogger, Injectable, LogLevel } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

interface LogMessageObject {
  name?: string;
  message: unknown;
  stack?: string;
  [key: string]: any;
}

@Injectable()
export class CustomLogger extends ConsoleLogger {
  constructor(
    context: string = 'Application',
    private readonly configService: ConfigService,
  ) {
    super(context);
    this.updateLogLevels();
  }

  private updateLogLevels() {
    const logLevelsConfig = this.configService.get<string>(
      'LOG_LEVELS',
      'log,error,warn,debug,verbose',
    );
    const logLevels = logLevelsConfig
      .split(',')
      .filter((level) => !!level) as LogLevel[];
    if (logLevels.length > 0) {
      this.setLogLevels(logLevels);
    }
  }

  private logMessage(
    level: LogLevel,
    originalMessage: any,
    logContext?: string,
    stack?: string,
  ) {
    if (!this.isLevelEnabled(level)) {
      return;
    }

    let processedLogContent: unknown;

    if (originalMessage instanceof Error) {
      processedLogContent = {
        name: originalMessage.name,
        message: originalMessage.message,
        stack: stack || originalMessage.stack,
      } satisfies LogMessageObject;
    } else if (
      typeof originalMessage === 'object' &&
      originalMessage !== null
    ) {
      const messageContent: LogMessageObject = { message: originalMessage };
      if (stack) {
        messageContent.stack = stack;
      }
      processedLogContent = messageContent;
    } else if (stack) {
      processedLogContent = {
        message: String(originalMessage),
        stack,
      } satisfies LogMessageObject;
    } else {
      processedLogContent = String(originalMessage);
    }

    const logObjectOutput = {
      timestamp: new Date().toISOString(),
      level,
      context: logContext || this.context,
      details: processedLogContent,
    };

    const output = `${JSON.stringify(logObjectOutput)}\n`;
    const writeStreamType =
      level === 'error' || level === 'warn' ? 'stderr' : 'stdout';
    process[writeStreamType].write(output);
  }

  log(message: any, context?: string) {
    this.logMessage('log', message, context);
  }

  error(message: any, stack?: string, context?: string) {
    this.logMessage('error', message, context, stack);
  }

  warn(message: any, context?: string) {
    this.logMessage('warn', message, context);
  }

  debug(message: any, context?: string) {
    this.logMessage('debug', message, context);
  }

  verbose(message: any, context?: string) {
    this.logMessage('verbose', message, context);
  }

  setContext(context: string) {
    super.setContext(context);
  }
}
