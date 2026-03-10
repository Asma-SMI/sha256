# XML Signature Demo - Spring Boot

## Prerequis
- Java 17
- Maven 3.9+

## Build
mvn clean package

## Run
java -jar target/xml-signature-demo-1.0.0.jar

## SHA du fichier brut
curl "http://localhost:8080/api/digest/raw?file=/data/D37940OC1.xml"

## Comparaison du DigestValue avec XSLT inline
curl "http://localhost:8080/api/digest/compare?businessXmlPath=/data/D37940OC1.xml&signatureXmlPath=/data/signature.xml"
