package com.example.signature.controller;

import com.example.signature.service.ReceptionProcessingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ProcessReceptionController {
    private final ReceptionProcessingService receptionProcessingService;

    public ProcessReceptionController(ReceptionProcessingService receptionProcessingService) {
        this.receptionProcessingService = receptionProcessingService;
    }

    //api de traiter les dossiers a partir dossier reception)
    @PostMapping("/process-reception")
    public ResponseEntity<?> processReception() {
        try {
            receptionProcessingService.processReceptionFolders();
            return ResponseEntity.ok("PROCESS_RECEPTION_OK");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("ERROR: " + e.getMessage());
        }
    }
}
