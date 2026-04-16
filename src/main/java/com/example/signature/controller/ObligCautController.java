package com.example.signature.controller;

import com.example.signature.dto.SignatureGenerationResult;
import com.example.signature.service.ObligCautService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/ttn")
public class ObligCautController {

    private final ObligCautService service;

    public ObligCautController(ObligCautService service) {
        this.service = service;
    }

    @PostMapping("/generate/{numDem}")
    public ResponseEntity<?> generate(@PathVariable String numDem) {
        try {
            SignatureGenerationResult result = service.generateSignatureFile(numDem);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Erreur: " + e.getClass().getName() + " - " + e.getMessage());
        }
    }

    // Mode batch manuel : traite tous les O06 trouvés
    @PostMapping("/generate-auto")
    public ResponseEntity<?> generateAuto() {
        try {
            int count = service.generateSignatureFilesAutoO06();
            return ResponseEntity.ok("Traitement batch terminé. Nombre de dossiers traités : " + count);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Erreur batch: " + e.getClass().getName() + " - " + e.getMessage());
        }
    }
}