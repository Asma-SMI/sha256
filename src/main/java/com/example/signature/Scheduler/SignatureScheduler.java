package com.example.signature.Scheduler;

import com.example.signature.service.ImailSignatureService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class SignatureScheduler {

    private static final Logger log = LoggerFactory.getLogger(SignatureScheduler.class);

    private final ImailSignatureService imailSignatureService;

    public SignatureScheduler(ImailSignatureService imailSignatureService) {
        this.imailSignatureService = imailSignatureService;
    }

    @Scheduled(cron = "0 * * * * *")
    public void runSignatureCheck() {
        try {
            log.info("Début traitement automatique des signatures...");
            imailSignatureService.comparePendingSignatures();
            log.info("Fin traitement signatures");
        } catch (Exception e) {
            log.error("Erreur dans le scheduler signature", e);
        }
    }
}