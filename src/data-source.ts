import 'reflect-metadata';
import { DataSource, DataSourceOptions } from 'typeorm';
import * as dotenv from 'dotenv';
import * as path from 'path';
import * as fs from 'fs';

const nodeEnv = process.env.NODE_ENV || 'development';
const envDevelopmentFilePath = path.resolve(__dirname, '..', `.env.${nodeEnv}`);
const envRootFilePath = path.resolve(__dirname, '..', '.env');

if (fs.existsSync(envDevelopmentFilePath)) {
  dotenv.config({ path: envDevelopmentFilePath });
} else if (fs.existsSync(envRootFilePath)) {
  dotenv.config({ path: envRootFilePath });
} else {
  console.warn(
    `Nenhum arquivo .env encontrado. Tentativa: ${envDevelopmentFilePath} ou ${envRootFilePath}. As variáveis de ambiente devem ser definidas externamente.`,
  );
}

const dbHost = process.env.DB_HOST;
const dbPort = process.env.DB_PORT;
const dbUsername = process.env.DB_USERNAME;
const dbPassword = process.env.DB_PASSWORD;
const dbName = process.env.DB_DATABASE;
const dbSynchronize = process.env.DB_SYNCHRONIZE;
const dbLogging = process.env.DB_LOGGING;
const dbSsl = process.env.DB_SSL;

if (!dbHost || !dbPort || !dbUsername || !dbPassword || !dbName) {
  throw new Error(
    'Uma ou mais variáveis de ambiente do banco de dados (DB_HOST, DB_PORT, DB_USERNAME, DB_PASSWORD, DB_DATABASE) não estão definidas. ' +
      `Verifique seus arquivos .env (tentativa: ${envDevelopmentFilePath} ou ${envRootFilePath}) ou se estão definidas no ambiente.`,
  );
}

export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  host: dbHost,
  port: parseInt(dbPort, 10),
  username: dbUsername,
  password: dbPassword,
  database: dbName,
  entities: [__dirname + '/modules/**/*.entity{.ts,.js}'],
  migrations: [path.join(__dirname, '/migrations/*{.ts,.js}')],
  synchronize: dbSynchronize === 'false',
  logging: dbLogging === 'true',
  ssl: dbSsl === 'true' ? { rejectUnauthorized: false } : false,
};

const AppDataSource = new DataSource(dataSourceOptions);

export default AppDataSource;
