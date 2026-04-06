package com.example.signature.controller;

import com.example.signature.dto.DigestComparisonResponse;
import com.example.signature.service.ImailSignatureService;
import com.example.signature.service.XmlDigestService;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Path;
import java.util.List;

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

    @PostMapping("/compare-auto")
    public List<DigestComparisonResponse> compareDigestAuto() throws Exception {
        return imailService.comparePendingSignatures();
    }


}
