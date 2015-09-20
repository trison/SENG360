import java.io.*;
import java.security.*;

class DigSig {

    public static void main(String[] args) throws IOException{

        /* Generate a DSA signature */
        String license = "license.txt";
        String line = null;

        if (args.length != 1) {
            System.out.println("Usage: GenSig nameOfFileToSign");
        }
         try {
            //Read license file
            FileReader fileReader = new FileReader(license);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            System.out.println("***License file contents:");
            while((line = bufferedReader.readLine()) != null) {
                System.out.println(line);
            } 
            bufferedReader.close();

            //Generate keys
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(1024, random);

            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey priv = pair.getPrivate();
            PublicKey pub = pair.getPublic();

            //Sign data
            Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
            dsa.initSign(priv);

            //Get data from file
            FileInputStream fis = new FileInputStream(license);
            BufferedInputStream bufin = new BufferedInputStream(fis);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = bufin.read(buffer)) >= 0) {
                dsa.update(buffer, 0, len);
            };
            bufin.close();

            //Generate signature
            byte[] realSig = dsa.sign();

            //Save signature and public key in files
            FileOutputStream sigfos = new FileOutputStream("sig");
            sigfos.write(realSig);
            sigfos.close();

            ///Save the public key in a file 
            byte[] key = pub.getEncoded();
            FileOutputStream keyfos = new FileOutputStream("suepk");
            keyfos.write(key);
            keyfos.close();

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
}