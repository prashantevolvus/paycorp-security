package com.paycorp.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;


public class XMLSignVerify {

  private static final Logger LOGGER = LoggerFactory.getLogger(XMLSignVerify.class);

  private static final String KEYSTORE_FILE="keys/indianbank.jks";
  private static final String KEYSTORE_PASS="serbia";
  private static final String BANK_KEYSTORE_ALIAS ="54eb870d9ad14386a54e3743ccadd88a";
  private static final String CLIENT_KEYSTORE_ALIAS = "TNWBD";

  public enum Operation {
    SIGNXML,
    VERIFYXML,
    NO_OPERATION
  }


  public  String signXML(String xmlFile) throws Exception {

    LOGGER.trace("Enter signXML");

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

    Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA512, null),
                      Collections.singletonList(
                        fac.newTransform(Transform.ENVELOPED,(TransformParameterSpec) null)
                      ),null, null
                    );

    SignedInfo si = fac.newSignedInfo(
                      fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null),
                      fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                      Collections.singletonList(ref)
                    );


    KeyStore ks = KeyStore.getInstance("JKS");
    ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PASS.toCharArray());
    KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry
        (BANK_KEYSTORE_ALIAS, new KeyStore.PasswordProtection(KEYSTORE_PASS.toCharArray()));
    X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

    KeyInfoFactory kif = fac.getKeyInfoFactory();
    List x509Content = new ArrayList();
    x509Content.add(cert.getSubjectX500Principal().getName());
    x509Content.add(cert);
    X509Data xd = kif.newX509Data(x509Content);
    KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));


    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(xmlFile));
    DOMSignContext dsc = new DOMSignContext
      (keyEntry.getPrivateKey(), doc.getDocumentElement());

    XMLSignature signature = fac.newXMLSignature(si, ki);
    signature.sign(dsc);
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer trans = tf.newTransformer();
    trans.transform(new DOMSource(doc), new StreamResult(os));

    LOGGER.trace("Exit signXML");

    return os.toString( StandardCharsets.UTF_8) ;

  }


  public  boolean verifyXML(String xmlString) throws Exception {

    LOGGER.trace("Enter verifyXML");

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");


    KeyStore ks = KeyStore.getInstance("JKS");
    ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PASS.toCharArray());

    PublicKey publicKey = ks.getCertificate(CLIENT_KEYSTORE_ALIAS).getPublicKey();
     


    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xmlString.getBytes("UTF-8")));
    // Find Signature element.
    NodeList nl =
        doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (nl.getLength() == 0) {
        LOGGER.error("Signature element not found in XML");
        throw new Exception("Cannot find Signature element");
    }

    // Create a DOMValidateContext and specify a KeySelector
    // and document context.
    DOMValidateContext valContext = new DOMValidateContext
        (publicKey, nl.item(0));

    // Unmarshal the XMLSignature.
    XMLSignature signature = fac.unmarshalXMLSignature(valContext);

    // Validate the XMLSignature.
    boolean coreValidity = signature.validate(valContext);
    if(coreValidity)
      LOGGER.info("XML SIGNATURE VALIDATION SUCCESS");
    else
      LOGGER.info("XML SIGNATURE VALIDATION FAILED");

    LOGGER.trace("Exit verifyXML Return"+ coreValidity);

    return coreValidity;

  }

  public static void main( String[] args ){
    try{

      String hexString = "b5ff6db1e2f1d27d294047b220516312da1b4ba899035692e893e16815fc9784";
      String content = Files.readString(Paths.get("ENC.XML"), StandardCharsets.UTF_8);
      Encryption enc = new Encryption();
      XMLSignVerify svXML = new XMLSignVerify();
      String plain = enc.decrypt(content, hexString);
      System.out.println(plain);
      svXML.verifyXML(plain);
    } catch(Exception e) {
         LOGGER.error("Exception raise " , e);
       }
  }

}
