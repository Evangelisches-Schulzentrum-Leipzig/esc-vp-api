'use strict';
const path = require('path');
const { Config } = require('./src/config');
const { Manager } = require('./src/manager');
const { createApi } = require('./src/api');
const { log } = require('./src/log');

const configFile = process.env.ESCVP_CONFIG || path.join(__dirname, 'config.json');
const config = new Config(configFile).load();
const manager = new Manager(config, log);
const api = createApi(manager, { clientDir: path.join(__dirname, '..', 'client') });

const { host, port } = config.data.server;
api.listen(port, host, () => {
    log.info(`Config: ${configFile}`);
    log.info(`Web client: http://${host}:${port}/  REST API: http://${host}:${port}/api`);
    manager.start();
});

function shutdown() {
    manager.stop();
    api.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
