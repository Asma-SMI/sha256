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
import javax.xml.transform.OutputKeys;
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
import java.util.Base64;

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
            throw new IllegalStateException("Aucune balise <Reference> principale trouvée dans la signature.");
        }

        String referenceUri = referenceElement.getAttribute("URI");
        String expectedDigest = getChildText(referenceElement, "DigestValue");
        String digestMethod = getAlgorithmUri(referenceElement, "DigestMethod");

        if (!SHA256_ALGO_URI.equals(digestMethod)) {
            throw new IllegalArgumentException("Algorithme non supporté pour cet exemple: " + digestMethod);
        }

        Element xsltStylesheet = extractXsltStylesheet(referenceElement);
        if (xsltStylesheet == null) {
            throw new IllegalStateException("Aucune XSLT trouvée dans la balise <Transform>.");
        }

        Document businessDoc = parseXml(businessXmlPath);

        TransformResult result = applyXsltToBytes(businessDoc, xsltStylesheet);

        String calculatedDigest = sha256Base64(result.bytes());
        String transformedXml = result.text();

        boolean matches = expectedDigest != null && expectedDigest.trim().equals(calculatedDigest);

        System.out.println("REFERENCE URI       = " + referenceUri);
        System.out.println("EXPECTED DIGEST     = " + expectedDigest);
        System.out.println("CALCULATED DIGEST   = " + calculatedDigest);
        System.out.println("MATCHES             = " + matches);
        System.out.println("TRANSFORMED XML     = " + transformedXml);
        System.out.println("TRANSFORMED HEX     = " + toHex(result.bytes()));
        System.out.println("TRANSFORMED LENGTH  = " + result.bytes().length);

        debugDigestVariants(expectedDigest, transformedXml);

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
        if (list.getLength() == 0) {
            return null;
        }
        return list.item(0).getTextContent().trim();
    }

    private String getAlgorithmUri(Element parent, String localName) {
        NodeList list = parent.getElementsByTagNameNS(XMLDSIG_NS, localName);
        if (list.getLength() == 0) {
            return null;
        }
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

    private TransformResult applyXsltToBytes(Document businessDoc, Element xsltStylesheet) throws Exception {
        Document xsltDocument = createStandaloneDocument(xsltStylesheet);

        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        Transformer transformer = factory.newTransformer(new DOMSource(xsltDocument));
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(businessDoc), new StreamResult(baos));

        byte[] transformedBytes = baos.toByteArray();
        String transformedText = new String(transformedBytes, StandardCharsets.UTF_8);

        return new TransformResult(transformedBytes, transformedText);
    }

    private Document createStandaloneDocument(Element element) throws Exception {
        DocumentBuilderFactory factory = secureDocumentBuilderFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document newDoc = builder.newDocument();

        Node importedNode = newDoc.importNode(element, true);
        newDoc.appendChild(importedNode);

        return newDoc;
    }

    private String sha256Base64(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data);
        return Base64.getEncoder().encodeToString(digest);
    }

    private void debugDigestVariants(String expectedDigest, String transformedXml) throws Exception {
        testVariant("RAW", expectedDigest, transformedXml);
        testVariant("TRIM", expectedDigest, transformedXml.trim());
        testVariant("NO_CR", expectedDigest, transformedXml.replace("\r", ""));
        testVariant("NO_LF", expectedDigest, transformedXml.replace("\n", ""));
        testVariant("NO_CRLF", expectedDigest, transformedXml.replace("\r", "").replace("\n", ""));
        testVariant("COLLAPSE_SPACES", expectedDigest, transformedXml.replaceAll(" +", " "));
        testVariant("NO_CRLF_AND_TRIM", expectedDigest, transformedXml.replace("\r", "").replace("\n", "").trim());
        testVariant(
                "NO_CRLF_TRIM_COLLAPSE_SPACES",
                expectedDigest,
                transformedXml.replace("\r", "").replace("\n", "").trim().replaceAll(" +", " ")
        );

        testVariant("NO_SELF_CLOSING", expectedDigest, replaceSelfClosingTags(transformedXml));
        testVariant("NO_SELF_CLOSING_TRIM", expectedDigest, replaceSelfClosingTags(transformedXml).trim());
        testVariant(
                "NO_SELF_CLOSING_NO_CRLF",
                expectedDigest,
                replaceSelfClosingTags(transformedXml).replace("\r", "").replace("\n", "")
        );
        testVariant(
                "NO_SELF_CLOSING_COLLAPSE_SPACES",
                expectedDigest,
                replaceSelfClosingTags(transformedXml).replaceAll(" +", " ")
        );
        testVariant(
                "NO_SELF_CLOSING_NO_CRLF_TRIM_COLLAPSE_SPACES",
                expectedDigest,
                replaceSelfClosingTags(transformedXml)
                        .replace("\r", "")
                        .replace("\n", "")
                        .trim()
                        .replaceAll(" +", " ")
        );
    }

    private void testVariant(String label, String expectedDigest, String value) throws Exception {
        String digest = sha256Base64(value.getBytes(StandardCharsets.UTF_8));
        boolean match = expectedDigest != null && expectedDigest.trim().equals(digest);

        System.out.println("VARIANT            = " + label);
        System.out.println("DIGEST             = " + digest);
        System.out.println("MATCH              = " + match);
        System.out.println("TEXT               = [" + value + "]");
        System.out.println("LENGTH             = " + value.length());
        System.out.println("--------------------------------------------");
    }

    private String replaceSelfClosingTags(String xml) {
        return xml.replaceAll("<([A-Za-z0-9_:-]+)\\s*/>", "<$1></$1>");
    }

    private String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private record TransformResult(byte[] bytes, String text) {
    }
}