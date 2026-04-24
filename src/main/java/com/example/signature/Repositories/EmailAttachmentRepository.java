package com.example.signature.Repositories;

import com.example.signature.Entities.EmailAttachment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

@Repository
public class EmailAttachmentRepository {
    private final JdbcTemplate jdbcTemplate;

    public EmailAttachmentRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }
    public void insert(Connection connection, EmailAttachment attachment) throws SQLException {
        String sql = """
                INSERT INTO SWF_MAIL.EMAIL_ATTACHMENTS (
                    EMAIL_ID,
                    FILENAME,
                    FILEDATA,
                    MIME_TYPE,
                    FILE_LOCATION
                ) VALUES (?, ?, ?, ?, ?)
                """;

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, attachment.getEmailId());
            ps.setString(2, attachment.getFilename());
            ps.setBytes(3, attachment.getFileData());
            ps.setString(4, attachment.getMimeType());
            ps.setString(5, attachment.getFileLocation());

            ps.executeUpdate();
        }
    }
    public int updateFileLocation(Long emailId, String filename, String fileLocation) {
        String sql = """
                UPDATE SWF_MAIL.EMAIL_ATTACHMENTS
                SET FILE_LOCATION = ?
                WHERE EMAIL_ID = ?
                  AND FILENAME = ?
                """;

        return jdbcTemplate.update(sql, fileLocation, emailId, filename);
    }

}
