package de.mtg.jplants;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PlantsUtilsTest {

    private static final String ENCODED_PUBLIC_KEY =
            "3059301306072a8648ce3d020106082a8648ce3d030107034200048b804b9900fd3c7a13707e14363210d8dc78daf337e914525fe51b77b4d5ebef7ba72cf4e30f17545437ef7a87ec44f493618e7bd8d33be7d809ffaa76536231";

    @Test
    void test() throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException,
            OperatorCreationException, InvalidAlgorithmParameterException {

        Security.addProvider(new BouncyCastleProvider());

        TBSCertificateLogEntry tbsCertificateLogEntry = new TBSCertificateLogEntry();
        tbsCertificateLogEntry.setVersion(new ASN1Integer(2));

        X500Name issuerDN = PlantsUtils.logDNExperimental("324731.1");
        tbsCertificateLogEntry.setIssuer(issuerDN);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2026, Calendar.JANUARY, 1, 0, 0, 0);
        calendar.set(Calendar.MILLISECOND, 0);
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.MONTH, 3);
        Date notAfter = calendar.getTime();
        tbsCertificateLogEntry.setStartDate(new Time(notBefore));
        tbsCertificateLogEntry.setEndDate(new Time(notAfter));

        X500Name subjectDN = new X500Name("CN=jplants");
        tbsCertificateLogEntry.setSubject(subjectDN);

        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Hex.decode(ENCODED_PUBLIC_KEY)));

        tbsCertificateLogEntry.setSubjectPublicKeyInfoAlgorithm(PlantsUtils.getSubjectPublicKeyAlgorithm(publicKey));
        tbsCertificateLogEntry.setSubjectPublicKeyInfoHash(PlantsUtils.defaultHashPublicKey(publicKey));
        Extension certificatePolicies = getCertificatePolicies("2.23.140.1.2.1");
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(certificatePolicies);
        tbsCertificateLogEntry.setExtensions(extensionsGenerator.generate());

        ASN1Primitive asn1Primitive = tbsCertificateLogEntry.toASN1Primitive();

        byte[] rawTBSCertificateLogEntry = asn1Primitive.getEncoded(ASN1Encoding.DER);

        assertEquals(
                "3081a5a003020102301a31183016060a2b0601040182da4b2f010c083332343733312e31301e170d3235313233313233303030305a170d3236303333313232303030305a30123110300e06035504030c076a706c616e7473301306072a8648ce3d020106082a8648ce3d030107042026845efb71ee235c28924aecf1ce5a1be1517fb71311e235a1c2a69d7cd9771fa317301530130603551d20040c300a3008060667810c010201",
                new String(Hex.encode(rawTBSCertificateLogEntry)));

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                issuerDN,
                BigInteger.ONE,
                notBefore,
                notAfter,
                subjectDN,
                SubjectPublicKeyInfo.getInstance(Hex.decode(ENCODED_PUBLIC_KEY)));
        certificateBuilder.addExtension(certificatePolicies);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);
        X509Certificate certificate =
                new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

        byte[] tbsCertificateLogEntryHash = PlantsUtils.hashLogEntry(tbsCertificateLogEntry, "SHA256");
        byte[] x509Hash = PlantsUtils.hashCertificate(certificate, "SHA256");
        ASN1Sequence certificateSequence = ASN1Sequence.getInstance(certificate.getEncoded());
        TBSCertificate tbsCertificate = TBSCertificate.getInstance(certificateSequence.getObjectAt(0));
        TBSCertificateLogEntry secondTbsCertificateLogEntry = PlantsUtils.fromTBS(tbsCertificate, "SHA256");
        byte[] secondTbsCertificateLogEntryHash = PlantsUtils.hashLogEntry(secondTbsCertificateLogEntry, "SHA256");

        assertEquals("983dc9e10e2282ccd789015d7bc3ad647103a02a7bf936cf38a14adcb3109ac8", new String(Hex.encode(x509Hash)));
        assertEquals("983dc9e10e2282ccd789015d7bc3ad647103a02a7bf936cf38a14adcb3109ac8", new String(Hex.encode(tbsCertificateLogEntryHash)));
        assertEquals("983dc9e10e2282ccd789015d7bc3ad647103a02a7bf936cf38a14adcb3109ac8", new String(Hex.encode(secondTbsCertificateLogEntryHash)));

    }

    private static Extension getCertificatePolicies(String policyOID) throws IOException {
        PolicyInformation[] policies = new PolicyInformation[1];
        List<PolicyInformation> policiesList = new ArrayList<>();
        PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier(policyOID));
        policiesList.add(policyInformation);
        CertificatePolicies cps = new CertificatePolicies(policiesList.toArray(policies));
        return new Extension(Extension.certificatePolicies, false, cps.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

}
