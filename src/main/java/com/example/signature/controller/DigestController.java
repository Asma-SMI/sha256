package com.example.signature.controller;

import com.example.signature.dto.DigestComparisonResponse;
import com.example.signature.service.ImailSignatureService;
import com.example.signature.service.XmlDigestService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;

@RestController
@RequestMapping("/api/digest")
public class DigestController {


    private final XmlDigestService service;
    private final ImailSignatureService imailService;

    public DigestController(ImailSignatureService imailService,XmlDigestService service) {
        this.imailService = imailService;
        this.service = service;
    }


    @GetMapping("/raw")
    public String rawDigest(@RequestParam String file) throws Exception {
        return service.calculateRawFileDigest(Path.of(file));
    }

    @GetMapping("/compare")
    public DigestComparisonResponse compareDigest(
            @RequestParam Long idImail,
            @RequestParam String signatureXmlPath
    ) throws Exception {
        return imailService.compareDigestFromImail(
                idImail,
                Path.of(signatureXmlPath)
        );
    }


}
