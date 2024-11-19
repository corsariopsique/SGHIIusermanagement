package com.sghii.gestorusuariossghii.servicio;

import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;
import java.util.Map;

public class UserManagementService {

    private final JdbcTemplate jdbcTemplate;

    public UserManagementService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String,Object>> listarUsuariosConRoles() {
        String query = """
            SELECT u.username, u.enabled, a.authority
            FROM users u
            LEFT JOIN authorities a ON u.username = a.username
            ORDER BY u.username
            """;

        List<Map<String, Object>> rows = jdbcTemplate.queryForList(query);

        return rows;

    }

}
