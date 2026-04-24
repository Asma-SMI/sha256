package com.example.signature.service;

import com.example.signature.Entities.SignatureProperties;
import com.example.signature.Repositories.EmailConfigRepository;
import com.example.signature.Repositories.ObligCautRepository;
import com.example.signature.dto.SignatureGenerationResult;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.Map;

//ce service pour generer xml et .sig nous meme (la sol à adapter prochainement)

@Service
public class ObligCautService {

    private static final String SIGNATURE_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String TIMESTAMP_NS = "http://www.ietf.org/rfc/rfc3161.txt";

    private static final String XSLT_STRING = """
            <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
                <xsl:output indent="yes" method="xml"/>
                <xsl:strip-space elements="*"/>
                <xsl:template match="@* | messages">
                    <xsl:copy>
                        <xsl:value-of select="name()"/>
                        <xsl:apply-templates>
                            <xsl:sort select="name()"/>
                            <xsl:sort select="."/>
                        </xsl:apply-templates>
                    </xsl:copy>
                </xsl:template>
                <xsl:template match="REFERENCE_TTN"/>
                <xsl:template match="DESTINATAIRE"/>
                <xsl:template match="PIECES_JOINTES"/>
            </xsl:stylesheet>
            """;

    private final ObligCautRepository repository;
    private final SignatureProperties properties;
    private final EmailQueueService emailQueueService;
    private final EmailConfigRepository emailConfigRepository;


    public ObligCautService(ObligCautRepository repository, SignatureProperties properties,
                            EmailQueueService emailQueueService,
                            EmailConfigRepository emailConfigRepository
                           ) {
        this.repository = repository;
        this.properties = properties;
        this.emailQueueService = emailQueueService;
        this.emailConfigRepository=emailConfigRepository;
      }
/// //
    public SignatureGenerationResult generateSignatureFile(String numDem) throws Exception {
        String xml = repository.getXmlFromOracle(numDem);

        if (xml == null || xml.isBlank()) {
            throw new IllegalStateException("XML vide retourné par Oracle pour NUM_DEM=" + numDem);
        }

        Path outputDir = Paths.get(properties.getOutputDir());
        Files.createDirectories(outputDir);

        String xmlFileName = numDem + ".xml";
        String numeroMessage = extractNumeroMessage(xml);
        String sigFileName = numeroMessage + "_sig.sig";

        // sous-dossier propre à la ligne
        Path recordDir = outputDir.resolve(numDem);
        Files.createDirectories(recordDir);

        Path xmlPath = recordDir.resolve(xmlFileName);
        Path sigPath = recordDir.resolve(sigFileName);

        Files.writeString(
                xmlPath,
                xml,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
        );

        KeyMaterial keyMaterial = loadKeyMaterial();

        //digestValueCertificate
        //prends le certificat chargé depuis le keystore puis le convertis en Base64 puis fais SHA-256 puis encodes en Base64 dans 'digestValueCertificate'
        String certificateBase64 = Base64.getEncoder().encodeToString(
                keyMaterial.certificate().getEncoded()
        );

        String modulusBase64 = Base64.getEncoder().encodeToString(
                keyMaterial.publicKey().getModulus().toByteArray()
        );

        String exponentBase64 = Base64.getEncoder().encodeToString(
                keyMaterial.publicKey().getPublicExponent().toByteArray()
        );

        // calcul de digestValueXml
        // lire le fichier XML puis appliques le XSLT puis fais SHA-256 puis encodes en Base64
        byte[] xmlBytes = Files.readAllBytes(xmlPath);
        byte[] transformedXmlBytes = applyXslt(xmlBytes, XSLT_STRING);
        String digestValueXml = sha256Base64(transformedXmlBytes);

        //calcul de digestValueTimestamp
        //fabriques un petit XML timestam puis fais SHA-256 puis encodes en Base64
        String timestampXml = buildTimestampXml();
        String digestValueTimestamp = sha256Base64(timestampXml.getBytes(StandardCharsets.UTF_8));

        String digestValueCertificate = sha256Base64(certificateBase64.getBytes(StandardCharsets.UTF_8));


        //construis SignedInfo et le canonicalises puis le signes avec la clé privée avec 'signRsaSha1Base64' puis encodes en Base64
        String signedInfoXml = buildSignedInfoXml(
                xmlFileName,
                digestValueXml,
                digestValueTimestamp,
                digestValueCertificate
        );
        byte[] canonicalSignedInfo = canonicalizeXml(signedInfoXml);
        String signatureValue = signRsaSha1Base64(canonicalSignedInfo, keyMaterial.privateKey());

        String sigXml = buildSignatureXml(
                signedInfoXml,
                signatureValue,
                modulusBase64,
                exponentBase64,
                timestampXml,
                certificateBase64
        );

        Files.writeString(
                sigPath,
                sigXml,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
        );

        File xmlFile = xmlPath.toFile();
        File sigFile = sigPath.toFile();

        String sender = emailConfigRepository.loadSender();
        String subject = "Flux TTN signe - " + numeroMessage;


        List<String> recipients = emailConfigRepository.loadRecipients();

        if (recipients == null || recipients.isEmpty()) {
            throw new IllegalStateException("Aucun destinataire configure dans SWF_MAIL.RECGONIZED_EMAIL_RECIPIENTS");
        }


        Long lastEmailId = null;

        for (String recipient : recipients) {
            Long emailId = emailQueueService.enqueueEmailWithAttachments(
                    sender,
                    recipient,
                    subject,
                    xml,
                    xmlFile,
                    sigFile
            );

            lastEmailId = emailId;
            System.out.println("EMAIL_QUEUE OK pour " + recipient + ", emailId=" + emailId);
        }
        return new SignatureGenerationResult(
                numDem,
                xmlPath.toString(),
                sigPath.toString(),
                digestValueXml,
                digestValueTimestamp,
                digestValueCertificate,
                signatureValue,
                lastEmailId
        );
    }

    ///
    public int generateSignatureFilesAutoO06() {
        List<String> numDems = repository.findNumDemToProcessO06();
        int processedCount = 0;

        for (String numDem : numDems) {
            try {
                String xml = repository.getXmlFromOracle(numDem);
                if (xml == null || xml.isBlank()) {
                    continue;
                }

                String numeroMessage = extractNumeroMessage(xml);
                Path recordDir = Paths.get(properties.getOutputDir(), numDem);
                Path sigPath = recordDir.resolve(numeroMessage + "_sig.sig");

                // anti-doublon simple : si le .sig existe déjà, on ignore
                if (Files.exists(sigPath)) {
                    continue;
                }

                generateSignatureFile(numDem);
                processedCount++;

            } catch (Exception e) {
                System.err.println("Erreur traitement auto numDem=" + numDem + " : " + e.getMessage());
            }
        }

        return processedCount;
    }

    ///
    private KeyMaterial loadKeyMaterial() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (var inputStream = Files.newInputStream(Paths.get(properties.getKeystorePath()))) {
            keyStore.load(inputStream, properties.getKeystorePassword().toCharArray());
        }

        Key key = keyStore.getKey(
                properties.getKeyAlias(),
                properties.getKeyPassword().toCharArray()
        );

        if (!(key instanceof PrivateKey privateKey)) {
            throw new IllegalStateException("Clé privée introuvable dans le keystore");
        }

        Certificate certificate = keyStore.getCertificate(properties.getKeyAlias());
        if (certificate == null) {
            throw new IllegalStateException("Certificat introuvable pour alias=" + properties.getKeyAlias());
        }

        if (!(certificate.getPublicKey() instanceof java.security.interfaces.RSAPublicKey publicKey)) {
            throw new IllegalStateException("La clé publique n'est pas RSA");
        }

        return new KeyMaterial(privateKey, certificate, publicKey);
    }

    private byte[] applyXslt(byte[] xmlBytes, String xslt) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        secureTransformerFactory(factory);

        Transformer transformer = factory.newTransformer(
                new StreamSource(new StringReader(xslt))
        );

        StringWriter writer = new StringWriter();
        transformer.transform(
                new StreamSource(new ByteArrayInputStream(xmlBytes)),
                new StreamResult(writer)
        );
        return writer.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String sha256Base64(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(input));
    }
/// ////
    private String buildTimestampXml() {
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String date = now.format(DateTimeFormatter.ofPattern("dd-MM-yyyy"));
        String time = now.format(DateTimeFormatter.ofPattern("HH:mm:ss 'UTC'"));

        return """
                <timestamp xmlns="%s"><date>%s</date><time>%s</time></timestamp>
                """.formatted(TIMESTAMP_NS, escapeXml(date), escapeXml(time));
    }
/// //////
    private String buildSignedInfoXml(
            String xmlFileName,
            String digestValueXml,
            String digestValueTimestamp,
            String digestValueCertificate
    ) {
        return """
                <SignedInfo xmlns="%s">
                  <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                  <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                  <Reference URI="%s">
                    <Transforms>
                      <Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
                        %s
                      </Transform>
                    </Transforms>
                    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <DigestValue>%s</DigestValue>
                  </Reference>
                  <Reference Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties" URI="#TimeStamp">
                    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <DigestValue>%s</DigestValue>
                  </Reference>
                  <Reference URI="#Certificat">
                    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <DigestValue>%s</DigestValue>
                  </Reference>
                </SignedInfo>
                """.formatted(
                SIGNATURE_NS,
                escapeXml(xmlFileName),
                XSLT_STRING,
                escapeXml(digestValueXml),
                escapeXml(digestValueTimestamp),
                escapeXml(digestValueCertificate)
        );
    }
/// ////
    private String buildSignatureXml(
            String signedInfoXml,
            String signatureValue,
            String modulusBase64,
            String exponentBase64,
            String timestampXml,
            String certificateBase64
    ) {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <Signature xmlns="%s">
                  %s
                  <SignatureValue>%s</SignatureValue>
                  <KeyInfo>
                    <KeyValue>
                      <RSAKeyValue>
                        <Modulus>%s</Modulus>
                        <Exponent>%s</Exponent>
                      </RSAKeyValue>
                    </KeyValue>
                  </KeyInfo>
                  <Object>
                    <SignatureProperties Id="">
                      <SignatureProperty Id="TimeStamp" Target="">
                        %s
                      </SignatureProperty>
                      <SignatureProperty Id="Certificat" Target="">%s</SignatureProperty>
                      <SignatureProperty Id="TimeStampToken" Target="">NoTimeStampToken</SignatureProperty>
                    </SignatureProperties>
                  </Object>
                </Signature>
                """.formatted(
                SIGNATURE_NS,
                signedInfoXml,
                breakBase64(signatureValue),
                breakBase64(modulusBase64),
                exponentBase64,
                timestampXml,
                escapeXml(certificateBase64)
        );
    }
/// ///
    private byte[] canonicalizeXml(String xml) throws Exception {
        Document document = parseXml(xml);

        TransformerFactory factory = TransformerFactory.newInstance();
        secureTransformerFactory(factory);

        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");

        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));

        return writer.toString().getBytes(StandardCharsets.UTF_8);
    }
/// ///
    private Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        disableExternalEntities(dbf);

        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new InputSource(new StringReader(xml)));
    }
/// //
    private String signRsaSha1Base64(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return Base64.getEncoder().encodeToString(signature.sign());
    }
/// /////
    private void secureTransformerFactory(TransformerFactory factory) {
        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        } catch (Exception ignored) {
        }
    }
/// /////
    private void disableExternalEntities(DocumentBuilderFactory dbf) {
        try {
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        } catch (Exception ignored) {
        }
    }
/// ///
    private String breakBase64(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        int chunkSize = 76;
        for (int i = 0; i < value.length(); i += chunkSize) {
            int end = Math.min(i + chunkSize, value.length());
            sb.append(value, i, end);
            if (end < value.length()) {
                sb.append(System.lineSeparator());
            }
        }
        return sb.toString();
    }

    ///
    private String escapeXml(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    private String extractNumeroMessage(String xml) throws Exception {
        var factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);

        var builder = factory.newDocumentBuilder();
        var doc = builder.parse(new org.xml.sax.InputSource(new java.io.StringReader(xml)));

        var nodeList = doc.getElementsByTagName("NUMERO_MESSAGE");

        if (nodeList.getLength() == 0) {
            throw new IllegalStateException("NUMERO_MESSAGE introuvable dans le XML");
        }

        return nodeList.item(0).getTextContent();
    }

    ///
    private record KeyMaterial(
            PrivateKey privateKey,
            Certificate certificate,
            java.security.interfaces.RSAPublicKey publicKey
    ) {
    }



}