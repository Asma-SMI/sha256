package com.example.signature.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;

@RestController
@RequestMapping("/api")
public class UploadController {

    //api d upload les dossiers depuis .bat dans notre serveur
    @PostMapping("/upload")
    public ResponseEntity<?> uploadFiles(
            @RequestParam("numDos") String numDos,
            @RequestParam("xml") MultipartFile xml,
            @RequestParam("sig") MultipartFile sig
    ) {
        try {
            String baseDir = "C:/messages/reception/" + numDos;
            File dir = new File(baseDir);
            if (!dir.exists() && !dir.mkdirs()) {
                throw new RuntimeException("Impossible de creer le dossier : " + baseDir);
            }

            File xmlFile = new File(dir, xml.getOriginalFilename());
            File sigFile = new File(dir, sig.getOriginalFilename());

            xml.transferTo(xmlFile);
            sig.transferTo(sigFile);

            System.out.println("==== UPLOAD OK ====");
            System.out.println("numDos = " + numDos);
            System.out.println("xml = " + xmlFile.getAbsolutePath());
            System.out.println("sig = " + sigFile.getAbsolutePath());

            return ResponseEntity.ok("UPLOAD_OK");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("ERROR: " + e.getMessage());
        }
    }
}
