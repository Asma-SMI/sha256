package com.example.signature.service;

import com.example.signature.Entities.Imail;
import com.example.signature.Repositories.ImailRepository;
import com.example.signature.dto.DigestComparisonResponse;
import org.springframework.stereotype.Service;

import java.nio.file.Path;

@Service
public class ImailSignatureService {
    private final ImailRepository imailRepository;
    private final XmlDigestService xmlDigestService;

    public ImailSignatureService(ImailRepository imailRepository,
                                 XmlDigestService xmlDigestService) {
        this.imailRepository = imailRepository;
        this.xmlDigestService = xmlDigestService;
    }

    public DigestComparisonResponse compareDigestFromImail(Long idImail, Path signatureXmlPath) throws Exception {
        Imail imail = imailRepository.findById(idImail)
                .orElseThrow(() -> new IllegalArgumentException("IMAIL not found: " + idImail));

        String bodyXml = imail.getBody();
        if (bodyXml == null || bodyXml.isBlank()) {
            throw new IllegalArgumentException("IMAIL.BODY is empty for id: " + idImail);
        }

        return xmlDigestService.compareDigest(bodyXml, signatureXmlPath);
    }


}
