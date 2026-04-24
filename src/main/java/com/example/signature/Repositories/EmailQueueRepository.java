package com.example.signature.Repositories;

import com.example.signature.Entities.EmailQueue;
import org.springframework.stereotype.Repository;

import java.sql.*;

@Repository
public class EmailQueueRepository {
        public Long insert(Connection connection, EmailQueue emailQueue) throws SQLException {

            String sql = """
                INSERT INTO SWF_MAIL.EMAIL_QUEUE (
                    SENDER,
                    RECIPIENTS,
                    CC,
                    BCC,
                    SUBJECT,
                    BODY,
                    BODY_MIME_TYPE
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """;

            try (PreparedStatement ps = connection.prepareStatement(sql)) {

                ps.setString(1, emailQueue.getSender());
                ps.setString(2, emailQueue.getRecipients());
                ps.setString(3, emailQueue.getCc());
                ps.setString(4, emailQueue.getBcc());
                ps.setString(5, emailQueue.getSubject());
                ps.setString(6, emailQueue.getBody());
                ps.setString(7, emailQueue.getBodyMimeType());

                ps.executeUpdate();
            }

            try (Statement st = connection.createStatement();
                 ResultSet rs = st.executeQuery("SELECT SWF_MAIL.ISEQ$$_82937.CURRVAL FROM dual")) {

                if (rs.next()) {
                    return rs.getLong(1);
                }
            }

            throw new SQLException("Impossible de récupérer l'ID généré");
        }
    }
