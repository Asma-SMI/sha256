package com.example.signature.service;

import com.example.signature.Repositories.EmailConfigRepository;
import com.example.signature.Repositories.ObligCautRepository;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;

@Service
public class ReceptionProcessingService {

    private final ObligCautRepository obligCautRepository;
    private final EmailQueueService emailQueueService;
    private final EmailConfigRepository emailConfigRepository;

    public ReceptionProcessingService(
            ObligCautRepository obligCautRepository,
            EmailQueueService emailQueueService,
            EmailConfigRepository emailConfigRepository
    ) {
        this.obligCautRepository = obligCautRepository;
        this.emailQueueService = emailQueueService;
        this.emailConfigRepository = emailConfigRepository;
    }

    public void processReceptionFolders() {

        File receptionRoot = new File("C:/messages/reception");
        File treatedRoot = new File("C:/messages/traites");

        if (!treatedRoot.exists()) {
            treatedRoot.mkdirs();
        }

        File[] folders = receptionRoot.listFiles(File::isDirectory);

        if (folders == null || folders.length == 0) {
            System.out.println("Aucun dossier dans reception.");
            return;
        }

        for (File folder : folders) {

            String folderName = folder.getName();

            try {
                System.out.println("==== TRAITEMENT RECEPTION ====");
                System.out.println("Dossier physique = " + folderName);

                File xmlFile = findFirstXmlOrMainFile(folder);
                File sigFile = findSigFile(folder);

                if (xmlFile == null || sigFile == null) {
                    System.out.println("XML ou SIG manquant pour dossier=" + folderName);
                    continue;
                }

                String xmlContent = Files.readString(xmlFile.toPath());
                String numDos = extractNumDosFromXml(xmlContent);

                System.out.println("NUM_DOS extrait XML = " + numDos);

                Map<String, Object> row = obligCautRepository.findPendingO06ByNumDos(numDos);

                if (row == null) {
                    System.out.println("Aucun DETAIL_OBLIG_CAUT O06 en statut B pour numDos=" + numDos);
                    continue;
                }

                Long idFlux = ((Number) row.get("ID_FLUX")).longValue();

                String numDemTtn = row.get("NUM_DEM_TTN") != null
                        ? row.get("NUM_DEM_TTN").toString()
                        : null;

                String codTypDoc = row.get("COD_TYP_DOC") != null
                        ? row.get("COD_TYP_DOC").toString()
                        : "UNKNOWN";

                if (numDemTtn == null || numDemTtn.isBlank()) {
                    System.out.println("NUM_DEM_TTN null pour numDos=" + numDos);
                    continue;
                }

                String sender = emailConfigRepository.loadSender();
                List<String> recipients = emailConfigRepository.loadRecipients();

                if (recipients == null || recipients.isEmpty()) {
                    throw new IllegalStateException("Aucun destinataire configure");
                }

                String subject = "Flux " + codTypDoc + " - NUM_DOS " + numDos;
                String body = obligCautRepository.getXmlFromOracle(numDemTtn);

                File targetFolder = new File(treatedRoot, folderName);

                if (targetFolder.exists()) {
                    deleteRecursively(targetFolder);
                }

                copyDirectory(folder, targetFolder);

                File xmlFileFinal = new File(targetFolder, xmlFile.getName());

                File sigFileFinal;
                if (sigFile.getParentFile().getName().equalsIgnoreCase("pjointe")) {
                    sigFileFinal = new File(
                            new File(targetFolder, "pJointe"),
                            sigFile.getName()
                    );
                } else {
                    sigFileFinal = new File(targetFolder, sigFile.getName());
                }

                for (String recipient : recipients) {
                    Long emailId = emailQueueService.enqueueEmailWithAttachments(
                            sender,
                            recipient,
                            subject,
                            body,
                            xmlFileFinal,
                            sigFileFinal
                    );

                    System.out.println("EMAIL_QUEUE OK pour " + recipient + ", emailId = " + emailId);
                }

                obligCautRepository.updateStatusToE(idFlux);

                deleteRecursively(folder);

                System.out.println("Dossier traite avec succes : " + folderName);

            } catch (Exception e) {
                e.printStackTrace();
                // En cas d'erreur, le dossier reste dans reception
            }
        }
    }

    private File findFirstXmlOrMainFile(File folder) {
        File[] xmlFiles = folder.listFiles((dir, name) ->
                name.toLowerCase().endsWith(".xml")
        );

        if (xmlFiles != null && xmlFiles.length > 0) {
            return xmlFiles[0];
        }

        File[] files = folder.listFiles(File::isFile);

        if (files != null && files.length > 0) {
            return files[0];
        }

        return null;
    }

    private File findSigFile(File folder) {
        File[] sigRoot = folder.listFiles((dir, name) ->
                name.toLowerCase().endsWith(".sig")
        );

        if (sigRoot != null && sigRoot.length > 0) {
            return sigRoot[0];
        }

        File pJointe = new File(folder, "pJointe");

        if (pJointe.exists() && pJointe.isDirectory()) {
            File[] sigFiles = pJointe.listFiles((dir, name) ->
                    name.toLowerCase().endsWith(".sig")
            );

            if (sigFiles != null && sigFiles.length > 0) {
                return sigFiles[0];
            }
        }

        return null;
    }

    private String extractNumDosFromXml(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        disableExternalEntities(dbf);

        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xml)));

        var nodeList = doc.getElementsByTagName("NUMERO_DOSSIER");

        if (nodeList.getLength() == 0) {
            throw new IllegalStateException("NUMERO_DOSSIER introuvable dans le XML");
        }

        return nodeList.item(0).getTextContent().trim();
    }

    private void copyDirectory(File source, File target) throws IOException {
        if (source.isDirectory()) {
            if (!target.exists() && !target.mkdirs()) {
                throw new IOException("Impossible de creer le dossier : " + target.getAbsolutePath());
            }

            File[] children = source.listFiles();
            if (children != null) {
                for (File child : children) {
                    copyDirectory(child, new File(target, child.getName()));
                }
            }
        } else {
            Files.copy(
                    source.toPath(),
                    target.toPath(),
                    StandardCopyOption.REPLACE_EXISTING
            );
        }
    }

    private void deleteRecursively(File file) {
        if (file == null || !file.exists()) {
            return;
        }

        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursively(child);
                }
            }
        }

        file.delete();
    }

    private void disableExternalEntities(DocumentBuilderFactory dbf) {
        try {
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        } catch (Exception ignored) {
        }
    }
}