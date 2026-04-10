package de.mtg.jplants;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PlantsUtils {

    private PlantsUtils() {
        // empty
    }

    public static X500Name logDNExperimental(String logID) {
        RDN[] idRdnaTrustAnchorID = {new RDN(new ASN1ObjectIdentifier("1.3.6.1.4.1.44363.47.1"), new DERUTF8String(logID))};
        return new X500Name(idRdnaTrustAnchorID);
    }

    public static X500Name logDN(String logID) {
        RDN[] idRdnaTrustAnchorID = {new RDN(new ASN1ObjectIdentifier("1.3.6.1.4.1.44363.47.1"), new ASN1RelativeOID(logID))};
        return new X500Name(idRdnaTrustAnchorID);
    }

    public static AlgorithmIdentifier getSubjectPublicKeyAlgorithm(PublicKey publicKey) {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        return subjectPublicKeyInfo.getAlgorithm();
    }

    public static byte[] rawHashPublicKey(PublicKey publicKey, String algorithm) {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        return rawHashPublicKey(subjectPublicKeyInfo, algorithm);
    }

    public static byte[] rawHashPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo, String algorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            return messageDigest.digest(subjectPublicKeyInfo.getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static ASN1OctetString hashPublicKey(PublicKey publicKey, String algorithm) {
        return new DEROctetString(rawHashPublicKey(publicKey, algorithm));
    }

    public static byte[] defaultRawHashPublicKey(PublicKey publicKey) {
        return rawHashPublicKey(publicKey, "SHA256");
    }

    public static ASN1OctetString defaultHashPublicKey(PublicKey publicKey) {
        return new DEROctetString(rawHashPublicKey(publicKey, "SHA256"));
    }

    public static byte[] hashLogEntry(TBSCertificateLogEntry tbsCertificateLogEntry, String algorithm) {

        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            messageDigest.update((byte) 0x00);
            messageDigest.update((byte) 0x00);
            messageDigest.update((byte) 0x01);
            ASN1Sequence sequence = ASN1Sequence.getInstance(tbsCertificateLogEntry);
            Enumeration objects = sequence.getObjects();
            while (objects.hasMoreElements()) {
                ASN1Encodable encodable = (ASN1Encodable) objects.nextElement();
                messageDigest.update(encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static byte[] hashLogEntry(TBSCertificateLogEntry tbsCertificateLogEntry) {
        return hashLogEntry(tbsCertificateLogEntry, "SHA256");
    }

    public static TBSCertificateLogEntry fromTBS(TBSCertificate tbsCertificate, String algorithm) {
        TBSCertificateLogEntry tbsCertificateLogEntry = new TBSCertificateLogEntry();
        tbsCertificateLogEntry.setVersion(tbsCertificate.getVersion());
        tbsCertificateLogEntry.setIssuer(tbsCertificate.getIssuer());
        tbsCertificateLogEntry.setStartDate(tbsCertificate.getStartDate());
        tbsCertificateLogEntry.setEndDate(tbsCertificate.getEndDate());
        tbsCertificateLogEntry.setSubject(tbsCertificate.getSubject());

        SubjectPublicKeyInfo subjectPublicKeyInfo = tbsCertificate.getSubjectPublicKeyInfo();
        tbsCertificateLogEntry.setSubjectPublicKeyInfoAlgorithm(subjectPublicKeyInfo.getAlgorithm());
        DEROctetString derOctetString = new DEROctetString(rawHashPublicKey(subjectPublicKeyInfo, algorithm));
        tbsCertificateLogEntry.setSubjectPublicKeyInfoHash(derOctetString);
        if (tbsCertificate.getIssuerUniqueId() != null) {
            tbsCertificateLogEntry.setIssuerUniqueID(tbsCertificate.getIssuerUniqueId());
        }
        if (tbsCertificate.getSubjectUniqueId() != null) {
            tbsCertificateLogEntry.setSubjectUniqueID(tbsCertificate.getSubjectUniqueId());
        }
        if (tbsCertificate.getExtensions() != null) {
            tbsCertificateLogEntry.setExtensions(tbsCertificate.getExtensions());
        }
        return tbsCertificateLogEntry;
    }

    public static TBSCertificateLogEntry fromTBS(TBSCertificate tbsCertificate) {
        return fromTBS(tbsCertificate, "SHA256");
    }

    public static byte[] hashCertificate(X509Certificate certificate, String algorithm) {
        try {
            ASN1Sequence certificateSequence = ASN1Sequence.getInstance(certificate.getEncoded());
            TBSCertificate tbsCertificate = TBSCertificate.getInstance(certificateSequence.getObjectAt(0));
            return hashTBSCertificate(tbsCertificate, algorithm);
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static byte[] hashTBSCertificate(TBSCertificate tbsCertificate, String algorithm) {

        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            messageDigest.update((byte) 0x00);
            messageDigest.update((byte) 0x00);
            messageDigest.update((byte) 0x01);
            ASN1Sequence sequence = ASN1Sequence.getInstance(tbsCertificate);
            ASN1Encodable firstObject = sequence.getObjectAt(0);
            boolean isVersionEncoded = false;
            if (firstObject instanceof ASN1TaggedObject) {
                isVersionEncoded = ((ASN1TaggedObject) firstObject).getTagNo() == 0;

            }

            int pkPosition = 6;
            if (isVersionEncoded) {
                messageDigest.update(firstObject.toASN1Primitive().getEncoded(ASN1Encoding.DER));
                messageDigest.update(sequence.getObjectAt(3).toASN1Primitive().getEncoded(ASN1Encoding.DER));
                messageDigest.update(sequence.getObjectAt(4).toASN1Primitive().getEncoded(ASN1Encoding.DER));
                messageDigest.update(sequence.getObjectAt(5).toASN1Primitive().getEncoded(ASN1Encoding.DER));
            } else {
                messageDigest.update(sequence.getObjectAt(2).toASN1Primitive().getEncoded(ASN1Encoding.DER));
                messageDigest.update(sequence.getObjectAt(3).toASN1Primitive().getEncoded(ASN1Encoding.DER));
                messageDigest.update(sequence.getObjectAt(4).toASN1Primitive().getEncoded(ASN1Encoding.DER));
                pkPosition = 5;
            }

            byte[] encoded = sequence.getObjectAt(pkPosition).toASN1Primitive().getEncoded(ASN1Encoding.DER);
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(encoded);
            messageDigest.update(spki.getAlgorithm().getEncoded(ASN1Encoding.DER));
            DEROctetString derOctetString = new DEROctetString(rawHashPublicKey(spki, algorithm));
            messageDigest.update(derOctetString.getEncoded(ASN1Encoding.DER));
            for (int i = pkPosition + 1; i < sequence.size(); i++) {
                messageDigest.update(sequence.getObjectAt(i).toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
