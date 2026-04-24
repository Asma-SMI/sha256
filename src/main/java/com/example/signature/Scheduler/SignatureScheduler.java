package com.example.signature.Scheduler;

import com.example.signature.service.ImailSignatureService;
import com.example.signature.service.ObligCautService;
import com.example.signature.service.ReceptionProcessingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class SignatureScheduler {

    private static final Logger log = LoggerFactory.getLogger(SignatureScheduler.class);

    private final ImailSignatureService imailSignatureService;
    private final ObligCautService obligCautService;
    private final ReceptionProcessingService receptionProcessingService;

    public SignatureScheduler(ImailSignatureService imailSignatureService,
                              ObligCautService obligCautService,
                              ReceptionProcessingService receptionProcessingService) {
        this.imailSignatureService = imailSignatureService;
        this.obligCautService = obligCautService;
        this.receptionProcessingService = receptionProcessingService;
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

    @Scheduled(cron = "0 * * * * *")
    public void processReceptionAuto() {
        try {
            log.info("=== Début traitement automatique reception ===");
            receptionProcessingService.processReceptionFolders();
            log.info("=== Fin traitement reception ===");
        } catch (Exception e) {
            log.error("Erreur dans le scheduler reception", e);
        }
    }

   /* @Scheduled(cron = "0 * * * * *")
    public void runEveryMinute() {
        int count = obligCautService.generateSignatureFilesAutoO06();
        System.out.println("Batch auto terminé. Nombre traité = " + count);
    } */
}