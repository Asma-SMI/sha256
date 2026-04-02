package com.example.signature.Entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;


@Entity
@Table(name = "IMAIL", schema = "gen")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Imail {
    @Id
    @Column(name = "ID_IMAIL", nullable = false)
    private Long idImail;

    @Column(name = "SENDER", length = 2048)
    private String sender;

    @Column(name = "SUBJECT", length = 1024)
    private String subject;

    @Lob
    @Column(name = "BODY")
    private String body;

    @Column(name = "MESSAGE_ID", length = 1024)
    private String messageId;

    @Column(name = "RECEIVED_AT")
    private LocalDateTime receivedAt;

    @Column(name = "ATTACHMENTS_PATH", length = 2048)
    private String attachmentsPath;

    @Column(name = "READ_AT")
    private LocalDateTime readAt;

    public Long getIdImail() {
        return idImail;
    }

    public void setIdImail(Long idImail) {
        this.idImail = idImail;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public String getMessageId() {
        return messageId;
    }

    public void setMessageId(String messageId) {
        this.messageId = messageId;
    }

    public LocalDateTime getReceivedAt() {
        return receivedAt;
    }

    public void setReceivedAt(LocalDateTime receivedAt) {
        this.receivedAt = receivedAt;
    }

    public String getAttachmentsPath() {
        return attachmentsPath;
    }

    public void setAttachmentsPath(String attachmentsPath) {
        this.attachmentsPath = attachmentsPath;
    }

    public LocalDateTime getReadAt() {
        return readAt;
    }

    public void setReadAt(LocalDateTime readAt) {
        this.readAt = readAt;
    }
}
