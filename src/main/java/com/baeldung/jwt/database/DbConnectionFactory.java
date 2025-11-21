package com.baeldung.jwt.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DbConnectionFactory implements ConnectionFactory {
    private String dbUrl;
    private String dbUser;
    private String dbPassword;

    public DbConnectionFactory(String dbUrl, String dbUser, String dbPassword) {
        this.dbUrl = dbUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
    }

    @Override
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }

    // ตรวจสอบว่าการเชื่อมต่อยัง valid อยู่หรือไม่
    public Connection getValidConnection() throws SQLException {
        Connection connection = getConnection();
        if (connection.isClosed()) {
            connection = getConnection();
        }
        return connection;
    }
}