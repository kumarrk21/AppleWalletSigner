package com.kk.signing;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

public class SigningInformationUtil {
	public SigningInformationUtil() {
		addBCProvider();
	}

	public SigningInformation loadSigningInformationFromPKCS12AndIntermediateCertificate(
			final InputStream pkcs12KeyStoreInputStream,
			final String keyStorePassword,
			final InputStream appleWWDRCAFileInputStream) throws IOException,
			NoSuchAlgorithmException, CertificateException, KeyStoreException,
			UnrecoverableKeyException {

		KeyStore pkcs12KeyStore = loadPKCS12File(pkcs12KeyStoreInputStream,
				keyStorePassword);
		X509Certificate appleWWDRCACert = loadDERCertificate(appleWWDRCAFileInputStream);

		return loadSigningInformationFromPKCS12AndIntermediateCertificate(
				pkcs12KeyStore, keyStorePassword.toCharArray(), appleWWDRCACert);
	}

	private SigningInformation loadSigningInformationFromPKCS12AndIntermediateCertificate(
			final KeyStore pkcs12KeyStore, final char[] keyStorePassword,
			final X509Certificate appleWWDRCACert) throws IOException,
			NoSuchAlgorithmException, CertificateException, KeyStoreException,
			UnrecoverableKeyException {

		Enumeration<String> aliases = pkcs12KeyStore.aliases();

		PrivateKey signingPrivateKey = null;
		X509Certificate signingCert = null;

		while (aliases.hasMoreElements()) {
			String aliasName = aliases.nextElement();

			Key key = pkcs12KeyStore.getKey(aliasName, keyStorePassword);
			if (key instanceof PrivateKey) {
				signingPrivateKey = (PrivateKey) key;
				Object cert = pkcs12KeyStore.getCertificate(aliasName);
				if (cert instanceof X509Certificate) {
					signingCert = (X509Certificate) cert;
					break;
				}
			}
		}

		return checkCertsAndReturnSigningInformationObject(signingPrivateKey,
				signingCert, appleWWDRCACert);
	}
	
	 private SigningInformation checkCertsAndReturnSigningInformationObject(PrivateKey signingPrivateKey, X509Certificate signingCert,
	            X509Certificate appleWWDRCACert) throws IOException, CertificateExpiredException, CertificateNotYetValidException {
	        if (signingCert == null || signingPrivateKey == null || appleWWDRCACert == null) {
	            throw new IOException("Couldn't load all the neccessary certificates/keys.");
	        }

	        // check the Validity of the Certificate to make sure it isn't expired
	        appleWWDRCACert.checkValidity();
	        signingCert.checkValidity();
	        return new SigningInformation(signingCert, signingPrivateKey, appleWWDRCACert);
	    }

	public KeyStore loadPKCS12File(final InputStream inputStreamOfP12,
			final String password) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		if (inputStreamOfP12 == null) {
			throw new IllegalArgumentException(
					"InputStream of key store must not be null");
		}
		KeyStore keystore = KeyStore.getInstance("PKCS12");

		keystore.load(inputStreamOfP12, password.toCharArray());
		return keystore;
	}

	public X509Certificate loadDERCertificate(
			final InputStream certificateInputStream) throws IOException,
			CertificateException {
		try {
			CertificateFactory certificateFactory = CertificateFactory
					.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
			Certificate certificate = certificateFactory
					.generateCertificate(certificateInputStream);
			if (certificate instanceof X509Certificate) {
				((X509Certificate) certificate).checkValidity();
				return (X509Certificate) certificate;
			}
			throw new IOException(
					"The key from the input stream could not be decrypted");
		} catch (IOException ex) {
			throw new IOException(
					"The key from the input stream could not be decrypted", ex);
		} catch (NoSuchProviderException ex) {
			throw new IOException(
					"The key from the input stream could not be decrypted", ex);
		}
	}
	
	public byte[] signManifest(byte[] manifestJSON, SigningInformation signingInformation){
		CMSProcessableByteArray content = new CMSProcessableByteArray(manifestJSON);
		try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
                    signingInformation.getSigningPrivateKey());

            final ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
            final Attribute signingAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new DERUTCTime(new Date())));
            signedAttributes.add(signingAttribute);

            // Create the signing table
            final AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
            // Create the table table generator that will added to the Signer builder
            final DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);

            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(
                    BouncyCastleProvider.PROVIDER_NAME).build()).setSignedAttributeGenerator(signedAttributeGenerator).build(sha1Signer,
                    signingInformation.getSigningCert()));

            List<X509Certificate> certList = new ArrayList<X509Certificate>();
            certList.add(signingInformation.getAppleWWDRCACert());
            certList.add(signingInformation.getSigningCert());

            JcaCertStore certs = new JcaCertStore(certList);

            generator.addCertificates(certs);

            CMSSignedData sigData = generator.generate(content, false);
            return sigData.getEncoded();
        } catch (Exception e) {
        	throw new IllegalArgumentException("Signing information not valid",e);
        }
		
	}

	private void addBCProvider() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}
}
