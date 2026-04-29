package com.example.signature.service;

import com.example.signature.Entities.DetailObligCaut;
import com.example.signature.Entities.Imail;
import com.example.signature.Repositories.DetailObligCautRepository;
import com.example.signature.Repositories.DonneesGeneralesRepository;
import com.example.signature.Repositories.ImailRepository;
import com.example.signature.dto.DigestComparisonResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

//ce service pour atteindre l objectif de reception des flux O04 (tous les logiques)

@Service
public class ImailSignatureService {
    private final ImailRepository imailRepository;
    private final XmlDigestService xmlDigestService;
    private final DetailObligCautRepository detailObligCautRepository;
    private final DonneesGeneralesRepository donneesGeneralesRepository;

    public ImailSignatureService(ImailRepository imailRepository,
                                 XmlDigestService xmlDigestService,
                                 DetailObligCautRepository detailObligCautRepository,
                                 DonneesGeneralesRepository donneesGeneralesRepository) {
        this.imailRepository = imailRepository;
        this.xmlDigestService = xmlDigestService;
        this.detailObligCautRepository = detailObligCautRepository;
        this.donneesGeneralesRepository=donneesGeneralesRepository;
    }
    @Transactional
    public DigestComparisonResponse compareDigestFromImail(Long idImail, Path signatureXmlPath) throws Exception {

        Imail imail = imailRepository.findById(idImail)
                .orElseThrow(() -> new RuntimeException("IMAIL not found"));

        String bodyXml = imail.getBody();

        DigestComparisonResponse response =
                xmlDigestService.compareDigest(bodyXml, signatureXmlPath);

        if (response.matches()) {
            detailObligCautRepository.updateStatusByIdImail(idImail, "V");
        }
        else {
            detailObligCautRepository.updateStatusByIdImail(idImail, "R");
        }

        return response;
    }

    @Transactional
    public List<DigestComparisonResponse> comparePendingSignatures() throws Exception {
        String basePath = donneesGeneralesRepository.findPathScanAs();

        if (basePath == null || basePath.isBlank()) {
            throw new IllegalStateException("PATH_SCAN_AS introuvable dans DONNES_GENERALES");
        }

        Path ttnDirectory = Path.of(basePath, "ttn");

        if (!Files.exists(ttnDirectory) || !Files.isDirectory(ttnDirectory)) {
            throw new IllegalStateException("Le répertoire TTN est introuvable : " + ttnDirectory);
        }

        List<DigestComparisonResponse> responses = new ArrayList<>();

        try (Stream<Path> files = Files.list(ttnDirectory)) {
            List<Path> signatureFiles = files
                    .filter(Files::isRegularFile)
                    .filter(this::isSignatureFile)
                    .toList();

            for (Path signatureFile : signatureFiles) {
                String numMessTtn = extractNumMessTtn(signatureFile.getFileName().toString());

                if (numMessTtn == null) {
                    continue;
                }

                Optional<DetailObligCaut> optional = detailObligCautRepository
                        .findByNumMessTtnAndStatus(numMessTtn, "X");

                if (optional.isEmpty()) {
                    continue;
                }

                DetailObligCaut detail = optional.get();

                DigestComparisonResponse response = compareDigestFromImail(
                        detail.getIdImail(),
                        signatureFile
                );

                responses.add(response);
            }
        }

        return responses;
    }

    private boolean isSignatureFile(Path path) {
        String fileName = path.getFileName().toString();
        return fileName.endsWith("_sig.sig");
    }

    private String extractNumMessTtn(String fileName) {
        if (fileName == null || !fileName.endsWith("_sig.sig")) {
            return null;
        }
        return fileName.substring(0, fileName.length() - "_sig.sig".length());
    }

}
