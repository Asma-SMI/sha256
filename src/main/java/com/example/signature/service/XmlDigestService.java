package com.example.signature.service;

import com.example.signature.dto.DigestComparisonResponse;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class XmlDigestService {

    private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XSLT_NS = "http://www.w3.org/1999/XSL/Transform";
    private static final String XSLT_ALGO = "http://www.w3.org/TR/1999/REC-xslt-19991116";
    private static final String SHA256_ALGO_URI = "http://www.w3.org/2001/04/xmlenc#sha256";

    public DigestComparisonResponse compareDigest(Path businessXmlPath, Path signatureXmlPath) throws Exception {
        Document signatureDoc = parseXml(signatureXmlPath);

        Element referenceElement = findMainDocumentReference(signatureDoc);
        if (referenceElement == null) {
            throw new IllegalStateException("No main <Reference> element found in signature.");
        }

        String referenceUri = referenceElement.getAttribute("URI");
        String expectedDigest = getChildText(referenceElement, "DigestValue");
        String digestMethod = getAlgorithmUri(referenceElement, "DigestMethod");

        if (!SHA256_ALGO_URI.equals(digestMethod)) {
            throw new IllegalArgumentException("Unsupported digest algorithm: " + digestMethod);
        }

        Element xsltStylesheet = extractXsltStylesheet(referenceElement);
        if (xsltStylesheet == null) {
            throw new IllegalStateException("No XSLT found in <Transform> element.");
        }

        Document businessDoc = parseXml(businessXmlPath);

        // Get the raw XSLT transform output bytes
        byte[] rawTransformBytes = applyXsltRaw(businessDoc, xsltStylesheet);
        String rawTransformText = new String(rawTransformBytes, StandardCharsets.UTF_8);

        // Build candidate byte representations:
        // Different XSLT processors/signers may produce slightly different byte sequences.
        // The most common differences are:
        //   1) With or without XML declaration
        //   2) With or without a newline (\n) after the XML declaration
        // We compute the digest for each candidate and pick the one matching expectedDigest.
        List<byte[]> candidates = buildCandidates(rawTransformBytes, rawTransformText);

        String calculatedDigest = null;
        byte[] matchingBytes = null;
        for (byte[] candidate : candidates) {
            String digest = sha256Base64(candidate);
            if (digest.equals(expectedDigest)) {
                calculatedDigest = digest;
                matchingBytes = candidate;
                break;
            }
        }

        // If no candidate matched, use the raw transform output as-is
        if (calculatedDigest == null) {
            calculatedDigest = sha256Base64(rawTransformBytes);
            matchingBytes = rawTransformBytes;
        }

        boolean matches = expectedDigest != null && expectedDigest.trim().equals(calculatedDigest);
        String transformedXml = new String(matchingBytes, StandardCharsets.UTF_8);

        return new DigestComparisonResponse(
                businessXmlPath.getFileName().toString(),
                referenceUri,
                expectedDigest,
                calculatedDigest,
                matches,
                transformedXml
        );
    }

    public String calculateRawFileDigest(Path xmlFile) throws Exception {
        byte[] bytes = Files.readAllBytes(xmlFile);
        return sha256Base64(bytes);
    }

    // ── XSLT transform ──────────────────────────────────────────────────

    private byte[] applyXsltRaw(Document businessDoc, Element xsltStylesheet) throws Exception {
        Document xsltDocument = createStandaloneDocument(xsltStylesheet);

        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        Transformer transformer = factory.newTransformer(new DOMSource(xsltDocument));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(businessDoc), new StreamResult(baos));
        return baos.toByteArray();
    }

    // ── Candidate builder ────────────────────────────────────────────────

    /**
     * Given the raw XSLT output, produce a list of plausible byte representations
     * that different signers may have used when computing the digest.
     *
     * Candidates produced (in order of priority):
     *   1. Raw output (as-is from the transformer)
     *   2. If output contains XML declaration without trailing \n → with \n inserted
     *   3. Output with XML declaration stripped entirely
     *   4. Variant 3 with leading/trailing whitespace trimmed
     */
    private List<byte[]> buildCandidates(byte[] rawBytes, String rawText) {
        List<byte[]> candidates = new ArrayList<>();

        // 1) Raw bytes as produced by the transformer
        candidates.add(rawBytes);

        if (rawText.startsWith("<?xml")) {
            int endDecl = rawText.indexOf("?>");
            if (endDecl != -1) {
                String decl = rawText.substring(0, endDecl + 2);
                String afterDecl = rawText.substring(endDecl + 2);

                // 2) Declaration + \n + rest  (if \n not already there)
                if (!afterDecl.startsWith("\n")) {
                    String withLf = decl + "\n" + afterDecl;
                    candidates.add(withLf.getBytes(StandardCharsets.UTF_8));
                }

                // 3) Declaration + \r\n + rest
                if (!afterDecl.startsWith("\r\n")) {
                    String withCrLf = decl + "\r\n" + afterDecl;
                    candidates.add(withCrLf.getBytes(StandardCharsets.UTF_8));
                }

                // 4) Body without declaration (strip leading whitespace from body)
                String body = afterDecl;
                candidates.add(body.getBytes(StandardCharsets.UTF_8));

                // 5) Body without declaration, trimmed
                String trimmedBody = body.trim();
                if (!trimmedBody.equals(body)) {
                    candidates.add(trimmedBody.getBytes(StandardCharsets.UTF_8));
                }
            }
        } else {
            // No XML declaration: try adding one
            String withDecl = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + rawText;
            candidates.add(withDecl.getBytes(StandardCharsets.UTF_8));

            String withDeclLf = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + rawText;
            candidates.add(withDeclLf.getBytes(StandardCharsets.UTF_8));
        }

        return candidates;
    }

    // ── XML parsing ──────────────────────────────────────────────────────

    private Document parseXml(Path path) throws Exception {
        DocumentBuilderFactory factory = secureDocumentBuilderFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();

        try (InputStream is = Files.newInputStream(path)) {
            return builder.parse(is);
        }
    }

    private DocumentBuilderFactory secureDocumentBuilderFactory() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        return factory;
    }

    // ── Signature XML extraction ─────────────────────────────────────────

    private Element findMainDocumentReference(Document signatureDoc) {
        NodeList references = signatureDoc.getElementsByTagNameNS(XMLDSIG_NS, "Reference");

        for (int i = 0; i < references.getLength(); i++) {
            Element ref = (Element) references.item(i);
            String uri = ref.getAttribute("URI");
            String type = ref.getAttribute("Type");

            if (uri != null && !uri.isBlank() && !uri.startsWith("#") && (type == null || type.isBlank())) {
                return ref;
            }
        }
        return null;
    }

    private String getChildText(Element parent, String localName) {
        NodeList list = parent.getElementsByTagNameNS(XMLDSIG_NS, localName);
        if (list.getLength() == 0) return null;
        return list.item(0).getTextContent().trim();
    }

    private String getAlgorithmUri(Element parent, String localName) {
        NodeList list = parent.getElementsByTagNameNS(XMLDSIG_NS, localName);
        if (list.getLength() == 0) return null;
        return ((Element) list.item(0)).getAttribute("Algorithm");
    }

    private Element extractXsltStylesheet(Element referenceElement) {
        NodeList transforms = referenceElement.getElementsByTagNameNS(XMLDSIG_NS, "Transform");

        for (int i = 0; i < transforms.getLength(); i++) {
            Element transform = (Element) transforms.item(i);
            String algo = transform.getAttribute("Algorithm");

            if (XSLT_ALGO.equals(algo)) {
                NodeList children = transform.getChildNodes();
                for (int j = 0; j < children.getLength(); j++) {
                    Node node = children.item(j);
                    if (node.getNodeType() == Node.ELEMENT_NODE
                            && "stylesheet".equals(node.getLocalName())
                            && XSLT_NS.equals(node.getNamespaceURI())) {
                        return (Element) node;
                    }
                }
            }
        }
        return null;
    }

    // ── DOM helpers ──────────────────────────────────────────────────────

    private Document createStandaloneDocument(Element element) throws Exception {
        DocumentBuilderFactory factory = secureDocumentBuilderFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document newDoc = builder.newDocument();
        Node importedNode = newDoc.importNode(element, true);
        newDoc.appendChild(importedNode);
        return newDoc;
    }

    // ── Crypto ───────────────────────────────────────────────────────────

    private String sha256Base64(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data);
        return Base64.getEncoder().encodeToString(digest);
    }
}
