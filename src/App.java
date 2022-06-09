import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;
import java.util.Scanner;
import java.io.ByteArrayInputStream;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.util.io.Streams;

import io.ipfs.api.IPFS;
import io.ipfs.api.NamedStreamable;
import io.ipfs.api.MerkleNode;
import io.ipfs.multihash.Multihash;

public class App {

    //Extra method to extract private key from .asc file if needed.
    public static PGPSecretKey readSecretKeyFromCol(InputStream in, long keyId) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());
    
        PGPSecretKey key = pgpSec.getSecretKey(keyId);
    
        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }

    @SuppressWarnings("rawtypes")
    public static PGPPublicKey readPublicKeyFromCol(InputStream in) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());
        PGPPublicKey key = null;
        Iterator rIt = pgpPub.getKeyRings();
        while (key == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();
            while (key == null && kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();
                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }
        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }

    //Decrypts file with input as the encrypted file in PGP format, the private/secret key of the user and the public key of encryptor.
    //The password is the GPG user password as set when configuring GPG on system, it is used to authenticate the secret key.
    //A defualt file name is needed to save the decrypted file to the system as needed.
    //NOTE: If the encrypted file is extracted from IPFS, the file will be uploaded to the directory after extraction.
    //NOTE: Even in case of IPFS file output, the file name must be manually added.
    public static void decryptFile(InputStream in, InputStream secKeyIn, InputStream pubKeyIn, char[] pass, String defaultFileName) throws IOException, PGPException, InvalidCipherTextException {
        Security.addProvider(new BouncyCastleProvider());

        PGPPublicKey pubKey = readPublicKeyFromCol(pubKeyIn);

        PGPSecretKey secKey = readSecretKeyFromCol(secKeyIn, pubKey.getKeyID());

        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact;


        PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());

        Object o = pgpF.nextObject();
        PGPEncryptedDataList encList;

        if (o instanceof PGPEncryptedDataList) {
            encList = (PGPEncryptedDataList) o;
        } else {
            encList = (PGPEncryptedDataList) pgpF.nextObject();
        }

        Iterator<PGPEncryptedData> itt = encList.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData encP = null;
        while (sKey == null && itt.hasNext()) {
            encP = (PGPPublicKeyEncryptedData)itt.next();
            secKey = readSecretKeyFromCol(new FileInputStream("PrivateKey.asc"), encP.getKeyID());
            sKey = secKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass));
        }
        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

        Object message = plainFact.nextObject();

        if (message instanceof PGPCompressedData)
        {
            PGPCompressedData c1 = (PGPCompressedData)message;
            pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
            
            message = pgpFact.nextObject();
        }

        if (message instanceof PGPLiteralData){
            PGPLiteralData ld = (PGPLiteralData)message;

            String outFileName = ld.getFileName();
            if (outFileName.length() == 0)
                {
                    outFileName = defaultFileName;
                }

            InputStream unc = ld.getInputStream();
            OutputStream fOut = new FileOutputStream(outFileName);

            Streams.pipeAll(unc, fOut, 8192);

            fOut.close();
        } else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("encrypted message contains a signed message - not literal data.");
        } else {
            throw new PGPException("message is not a simple encrypted file - type unknown.");
        }

        //Integrity checking for file with integrity checking feature.
        if (encP.isIntegrityProtected()){

            if (!encP.verify()) {
                System.err.println("Integrity check failed");
            } else {
                System.err.println("Integrity check passed");
            }
        } else {
            System.err.println("No integrity checks possible as file does not have integrity checks feature");
        }
    }

    //Encrypts file in PGP format with inputs as the file, the public key converted from .asc file in main method.
    //Additional functionality allow it to have integrity checks enabled and ascii armoring as per user discretion.
    //Ascii armoring is a time consuming process hence there will be performance loss of the program for using feature.
    public static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean integrity, boolean armor) throws IOException, NoSuchProviderException, PGPException {
        if(armor){
            out = new ArmoredOutputStream(out);
        }

        Security.addProvider(new BouncyCastleProvider());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));

        comData.close();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES).setWithIntegrityPacket(integrity).setSecureRandom(new SecureRandom()));

        cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

        byte[] bytes = bOut.toByteArray();

        OutputStream cOut = cPk.open(out, bytes.length);

        cOut.write(bytes);

        cOut.close();

        out.close();
    }

    public static void main(String [] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        //Warning for Scanner never closed is displayed due to the infinite running possibility of the loop.
        //scanner.close() is added at the end of the code and the resource will be closed when a user terminates program.
        //Hence, warning to be ignored.
        Scanner scanner = new Scanner(System.in);
        
        IPFS ipfs= new IPFS("localhost", 5001);
        ipfs.refs.local();

        while(true){
            System.out.println("Choose your action: Encrypt/Decrypt");
            String action = scanner.nextLine();

            if(action.equals("Encrypt")){

                //Files must be added in the formats specified by the code for correct operation.
                System.out.println("Give the path directories of the following files needed as prompted");
                System.out.println("Optionally, move the files to the working directory of the program and just give their name");

                System.out.println("File to be encrypted with extension (preferably jpeg/jpg): ");
                String fileName = scanner.nextLine();

                System.out.println("Your public key in ascii (.asc) format: ");
                String publicKey = scanner.nextLine();

                System.out.println("Should the file have integrity checking options? Y/N");
                String integrity = scanner.nextLine();

                boolean integritySelection = false;
                if(integrity.equals("Y")) integritySelection = true;

                System.out.println("Should the file be ascii armored? Y/N");
                System.out.println("NOTE: The ascii armoring process will take a while but it will give a more integral output overall.");
                String armor = scanner.nextLine();

                boolean armorSelection = false;
                if(armor.equals("Y")) armorSelection = true;

                try{
                    PGPPublicKey pubKey = readPublicKeyFromCol(new FileInputStream(publicKey));
                    encryptFile(new FileOutputStream("encryptedFileOutput.gpg"), fileName, pubKey, integritySelection, armorSelection);
                } catch(PGPException e){
                    System.out.println("exception: " + e.getMessage());
                }

                System.out.println("do you wish to upload the encrypted file to IPFS storage? Y/N");
        
                String option = scanner.nextLine();
                boolean ipfsSelection = false;

                if (option.equals("Y")) ipfsSelection = true;

                if(ipfsSelection){
                    try {
                        NamedStreamable.FileWrapper file = new NamedStreamable.FileWrapper(new File("encryptedFileOutput.gpg"));
                        MerkleNode response = ipfs.add(file).get(0);
                        System.out.println("Hash (base 58): " + response.hash.toBase58());
                        } catch (IOException ex) {
                        throw new RuntimeException("Error whilst communicating with the IPFS node", ex);
                    }
                }

            } else if(action.equals("Decrypt")){
/* 
                //Theoretically to obtain file to be decrypted from IPFS
                //Cannot add functionality currently because unable to convert byte array (with hidden data) to gpg file.
                System.out.println("Would you like to get the image file to be decrypted from IPFS? Y/N");
                String getIPFSFile = scanner.nextLine();
        
                boolean obtain = false;
                if(getIPFSFile.equals("Y")) obtain = true;

                if(obtain){
                    System.out.println("Give the hash of the file you would like to obtain in base 58 format");
                    String hash = scanner.nextLine();

                    Multihash filePointer = Multihash.fromBase58(hash);
                    byte[] fileContents = ipfs.cat(filePointer);
            
                    ByteArrayInputStream inStreambj = new ByteArrayInputStream(fileContents);
    
                }
*/
                System.out.println("Give the path directories of the following files needed as prompted");
                System.out.println("Optionally, move the files to the working directory of the program and just give their name");

                System.out.println("Encrypted file name with extension gpg: ");
                String fileName = scanner.nextLine();

                System.out.println("Your private key in ascii (.asc) format: ");
                String privateKey = scanner.nextLine();

                System.out.println("Decryption public key in ascii (.asc) format: ");
                String publicKey = scanner.nextLine();                  

                System.out.println("Mention the name of the file as you would like after decryption: ");
                String defaultFileName = scanner.nextLine();

                decryptFile(new FileInputStream(fileName), new FileInputStream(privateKey), new FileInputStream(publicKey), "yourKeyPassword".toCharArray(), defaultFileName);

            } else {
                System.out.println("Error: Please make selection as stated");
            }

            System.out.println("Would you like to terminate the program or continue operation? Terminate/Continue");
            String continuation = scanner.nextLine();

            if(continuation.equals("Terminate")) break;
        }
        scanner.close();
    }    
}