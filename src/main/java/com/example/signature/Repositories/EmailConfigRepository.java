package com.example.signature.Repositories;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class EmailConfigRepository {
    private final JdbcTemplate jdbcTemplate;

    public EmailConfigRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public String loadSender() {
        String sql = """
                SELECT ADDRESS_MAIL
                FROM SWF_MAIL.RECGONIZED_EMAIL_SENDER
                FETCH FIRST 1 ROWS ONLY
                """;

        return jdbcTemplate.queryForObject(sql, String.class);
    }
    public List<String> loadRecipients() {
        String sql = """
            SELECT ADDRESS_MAIL
            FROM SWF_MAIL.RECGONIZED_EMAIL_RECIPIENTS
            ORDER BY ADDRESS_MAIL
            """;

        return jdbcTemplate.queryForList(sql, String.class);
    }
}
