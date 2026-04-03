package com.example.signature.service;

import com.example.signature.Entities.Imail;
import com.example.signature.Repositories.DetailObligCautRepository;
import com.example.signature.Repositories.ImailRepository;
import com.example.signature.dto.DigestComparisonResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Path;

@Service
public class ImailSignatureService {
    private final ImailRepository imailRepository;
    private final XmlDigestService xmlDigestService;
    private final DetailObligCautRepository detailObligCautRepository;

    public ImailSignatureService(ImailRepository imailRepository,
                                 XmlDigestService xmlDigestService,
                                 DetailObligCautRepository detailObligCautRepository) {
        this.imailRepository = imailRepository;
        this.xmlDigestService = xmlDigestService;
        this.detailObligCautRepository = detailObligCautRepository;
    }
    @Transactional
    public DigestComparisonResponse compareDigestFromImail(Long idImail, Path signatureXmlPath) throws Exception {

        Imail imail = imailRepository.findById(idImail)
                .orElseThrow(() -> new RuntimeException("IMAIL not found"));

        String bodyXml = imail.getBody();

        DigestComparisonResponse response =
                xmlDigestService.compareDigest(bodyXml, signatureXmlPath);

        if (response.matches()) {
            detailObligCautRepository.updateStatusByIdImail(idImail, "V");
        }
        else {
            detailObligCautRepository.updateStatusByIdImail(idImail, "R");
        }

        return response;
    }


}
