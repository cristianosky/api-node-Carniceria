const mysql = require('mysql');
require('dotenv').config();

const dbConfig = {
    host: process.env.MYSQL_ADDON_HOST,
    user: process.env.MYSQL_ADDON_USER,
    password: process.env.MYSQL_ADDON_PASSWORD,
    database: process.env.MYSQL_ADDON_DB,
    port: process.env.MYSQL_ADDON_PORT
};

function getDbConnection() {
    const connection = mysql.createConnection(dbConfig);
    connection.connect((err) => {
        if (err) {
            console.error('Error connecting to the database:', err);
        }
    });
    return connection;
}

function closeDbConnection(connection) {
    connection.end((err) => {
        if (err) {
            console.error('Error closing the database connection:', err);
        }
    });
}

module.exports = { getDbConnection, closeDbConnection };
