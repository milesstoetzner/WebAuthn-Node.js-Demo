var winston = require("winston");

var logger = new winston.Logger({
    transports: [
        new winston.transports.Console({
            level: 'debug',
            timestamp: function () {
                return (new Date()).toISOString();
            },
            colorize: true
        })
    ]
});

module.exports = logger;