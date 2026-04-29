package com.example.signature.controller;

import com.example.signature.Repositories.DonneesGeneralesRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;

@RestController
@RequestMapping("/api")
public class UploadController {

    private final DonneesGeneralesRepository donneesGeneralesRepository;

    public UploadController(DonneesGeneralesRepository donneesGeneralesRepository) {
        this.donneesGeneralesRepository = donneesGeneralesRepository;
    }

    @PostMapping("/upload")
    public ResponseEntity<?> uploadFiles(
            @RequestParam("numDos") String numDos,
            @RequestParam("xml") MultipartFile xml,
            @RequestParam("sig") MultipartFile sig
    ) {
        try {
            String basePath = donneesGeneralesRepository.findPathScanAs().trim();

            String receptionPath = basePath + File.separator + "reception" + File.separator + numDos;

            File dir = new File(receptionPath);

            if (!dir.exists() && !dir.mkdirs()) {
                throw new RuntimeException("Impossible de creer le dossier : " + receptionPath);
            }

            File xmlFile = new File(dir, xml.getOriginalFilename());
            File sigFile = new File(dir, sig.getOriginalFilename());

            xml.transferTo(xmlFile);
            sig.transferTo(sigFile);

            System.out.println("==== UPLOAD OK ====");
            System.out.println("numDos = " + numDos);
            System.out.println("basePath = " + basePath);
            System.out.println("xml = " + xmlFile.getAbsolutePath());
            System.out.println("sig = " + sigFile.getAbsolutePath());

            return ResponseEntity.ok("UPLOAD_OK");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("ERROR: " + e.getMessage());
        }
    }
}