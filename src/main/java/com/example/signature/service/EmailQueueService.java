package com.example.signature.service;

import com.example.signature.Entities.EmailAttachment;
import com.example.signature.Entities.EmailQueue;
import com.example.signature.Repositories.EmailAttachmentRepository;
import com.example.signature.Repositories.EmailQueueRepository;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.io.File;
import java.nio.file.Files;
import java.sql.Connection;

//ce service pour atteindre l objectif de envoi des flux O06 (tous les logiques)

@Service
public class EmailQueueService {
    private final DataSource dataSource;
    private final EmailQueueRepository emailQueueRepository;
    private final EmailAttachmentRepository emailAttachmentRepository;

    public EmailQueueService(
            DataSource dataSource,
            EmailQueueRepository emailQueueRepository,
            EmailAttachmentRepository emailAttachmentRepository
    ) {
        this.dataSource = dataSource;
        this.emailQueueRepository = emailQueueRepository;
        this.emailAttachmentRepository = emailAttachmentRepository;
    }

    public Long enqueueEmailWithAttachments(
            String sender,
            String recipients,
         //   String cc,
          //  String bcc,
            String subject,
            String body,
            File xmlFile,
            File sigFile
    ) throws Exception {

        try (Connection connection = dataSource.getConnection()) {

            connection.setAutoCommit(false);

            try {

                // 1. INSERT EMAIL_QUEUE
                EmailQueue emailQueue = new EmailQueue();
                emailQueue.setSender(sender);
                emailQueue.setRecipients(recipients);
              //  emailQueue.setCc(cc);
              //  emailQueue.setBcc(bcc);
                emailQueue.setSubject(subject);
                emailQueue.setBody(body);
                emailQueue.setBodyMimeType("application/xml");

                Long emailId = emailQueueRepository.insert(connection, emailQueue);

                System.out.println(">>> EMAIL_ID généré = " + emailId);

                // 2. INSERT ATTACHMENT XML
                EmailAttachment xmlAttachment = new EmailAttachment();
                xmlAttachment.setEmailId(emailId);
                xmlAttachment.setFilename(xmlFile.getName());
                xmlAttachment.setFileData(Files.readAllBytes(xmlFile.toPath()));
                xmlAttachment.setMimeType("application/xml");
                xmlAttachment.setFileLocation(xmlFile.getAbsolutePath());

                emailAttachmentRepository.insert(connection, xmlAttachment);

                // 3. INSERT ATTACHMENT SIG
                EmailAttachment sigAttachment = new EmailAttachment();
                sigAttachment.setEmailId(emailId);
                sigAttachment.setFilename(sigFile.getName());
                sigAttachment.setFileData(Files.readAllBytes(sigFile.toPath()));
                sigAttachment.setMimeType("application/xml");
                sigAttachment.setFileLocation(sigFile.getAbsolutePath());

                emailAttachmentRepository.insert(connection, sigAttachment);

                connection.commit();
                return emailId;

            } catch (Exception e) {
                connection.rollback();
                throw e;
            }
        }
    }
}
