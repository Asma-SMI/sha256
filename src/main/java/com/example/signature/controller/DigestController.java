package com.example.signature.controller;

import com.example.signature.dto.DigestComparisonResponse;
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

    public DigestController(XmlDigestService service) {
        this.service = service;
    }

    @GetMapping("/raw")
    public String rawDigest(@RequestParam String file) throws Exception {
        return service.calculateRawFileDigest(Path.of(file));
    }

    @GetMapping("/compare")
    public DigestComparisonResponse compareDigest(
            @RequestParam String businessXmlPath,
            @RequestParam String signatureXmlPath
    ) throws Exception {
        return service.compareDigest(Path.of(businessXmlPath), Path.of(signatureXmlPath));
    }
}
