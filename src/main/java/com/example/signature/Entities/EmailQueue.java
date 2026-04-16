package com.example.signature.Entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "EMAIL_QUEUE", schema = "SWF_MAIL")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class EmailQueue {

    @Id
    private Long id;
    private String sender;
    private String recipients;
    private String cc;
    private String bcc;
    private String subject;
    private String body;
    private String bodyMimeType;


}
