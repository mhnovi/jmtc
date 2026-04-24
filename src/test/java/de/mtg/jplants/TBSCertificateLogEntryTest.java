package de.mtg.jplants;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import de.mtg.jplants.utils.PlantsUtils;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TBSCertificateLogEntryTest {

    private static final String ENCODED_PUBLIC_KEY =
            "3059301306072a8648ce3d020106082a8648ce3d030107034200048b804b9900fd3c7a13707e14363210d8dc78daf337e914525fe51b77b4d5ebef7ba72cf4e30f17545437ef7a87ec44f493618e7bd8d33be7d809ffaa76536231";

    @Test
    void toASN1Primitive() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        TBSCertificateLogEntry tbsCertificateLogEntry = new TBSCertificateLogEntry();
        tbsCertificateLogEntry.setVersion(new ASN1Integer(2));

        tbsCertificateLogEntry.setIssuer(PlantsUtils.logDNExperimental("324731.1"));

        {
            Calendar cal = Calendar.getInstance();
            cal.set(2026, Calendar.JANUARY, 1, 0, 0, 0);
            cal.set(Calendar.MILLISECOND, 0);
            Date oldDate = cal.getTime();
            cal.add(Calendar.MONTH, 3);
            Date newDate = cal.getTime();
            tbsCertificateLogEntry.setStartDate(new Time(oldDate));
            tbsCertificateLogEntry.setEndDate(new Time(newDate));
        }

        tbsCertificateLogEntry.setSubject(new X500Name("CN=jplants"));

        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Hex.decode(ENCODED_PUBLIC_KEY)));

        System.out.println(publicKey);

        tbsCertificateLogEntry.setSubjectPublicKeyInfoAlgorithm(PlantsUtils.getSubjectPublicKeyAlgorithm(publicKey));
        tbsCertificateLogEntry.setSubjectPublicKeyInfoHash(PlantsUtils.defaultHashPublicKey(publicKey));

        Extension certificatePolicies = getCertificatePolicies("2.23.140.1.2.1");
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(certificatePolicies);
        tbsCertificateLogEntry.setExtensions(extensionsGenerator.generate());

        ASN1Primitive rawTBSCertificateLogEntry = tbsCertificateLogEntry.toASN1Primitive();

        assertEquals(
                "3081a5a003020102301a31183016060a2b0601040182da4b2f010c083332343733312e31301e170d3235313233313233303030305a170d3236303333313232303030305a30123110300e06035504030c076a706c616e7473301306072a8648ce3d020106082a8648ce3d030107042026845efb71ee235c28924aecf1ce5a1be1517fb71311e235a1c2a69d7cd9771fa317301530130603551d20040c300a3008060667810c010201",
                new String(Hex.encode(rawTBSCertificateLogEntry.getEncoded(ASN1Encoding.DER))));

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
