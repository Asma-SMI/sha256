package com.example.signature.Entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "EMAIL_ATTACHMENTS", schema = "SWF_MAIL")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class EmailAttachment {

    @Id
    private Long id;
    private Long emailId;
    private String filename;
    private byte[] fileData;
    private String mimeType;
    private String fileLocation;
}
