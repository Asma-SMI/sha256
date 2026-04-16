package com.example.signature.Entities;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Setter
@Getter
@Component
@ConfigurationProperties(prefix = "signature")
public class SignatureProperties {

    private String outputDir;
    private String keystorePath;
    private String keystorePassword;
    private String keyAlias;
    private String keyPassword;
    private String recipients;
    private String sourceTable;


}