// Deliberately vulnerable Java sample: SQL injection and command injection.
// DO NOT use this code in production.
package com.example.vulnforge;

import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class VulnerableService {

    // vulnforge-static: sql-injection
    public ResultSet findUser(Connection conn, String userId) throws Exception {
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return stmt.executeQuery(query);
    }

    // vulnforge-static: command-injection
    public void runCommand(String host) throws IOException {
        Runtime.getRuntime().exec("ping -c 4 " + host);
    }
}
