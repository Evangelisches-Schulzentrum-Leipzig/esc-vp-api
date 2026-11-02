'use strict';

const stamp = () => new Date().toISOString();
const silent = process.env.ESCVP_LOG === 'silent';

const log = {
    info: (...a) => !silent && console.log(stamp(), 'INFO ', ...a),
    warn: (...a) => !silent && console.warn(stamp(), 'WARN ', ...a),
    error: (...a) => !silent && console.error(stamp(), 'ERROR', ...a),
};

module.exports = { log };
