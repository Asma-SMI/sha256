package com.example.signature.dto;

import lombok.Getter;

@Getter
public class SignatureGenerationResult {
    private final String numDem;
    private final String xmlPath;
    private final String sigPath;
    private final String digestValueXml;
    private final String digestValueTimestamp;
    private final String digestValueCertificate;
    private final String signatureValue;
    private final Long emailId;

    public SignatureGenerationResult(
            String numDem,
            String xmlPath,
            String sigPath,
            String digestValueXml,
            String digestValueTimestamp,
            String digestValueCertificate,
            String signatureValue,
            Long emailId
    ) {
        this.numDem = numDem;
        this.xmlPath = xmlPath;
        this.sigPath = sigPath;
        this.digestValueXml = digestValueXml;
        this.digestValueTimestamp = digestValueTimestamp;
        this.digestValueCertificate = digestValueCertificate;
        this.signatureValue = signatureValue;
        this.emailId = emailId;
    }

}
