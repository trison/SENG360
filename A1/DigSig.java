import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;


class DigSig {

    public static void main(String[] args) throws IOException{

        /*** Generate a DSA signature ***/
        String license = "license.txt";
        String line = null;

        if (args.length != 1) {
            System.out.println("Usage: GenSig nameOfFileToSign");
        }
        try {

            //Generate keys
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(1024, random);

            //Get public and private key pair
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
            String contents = new String(buffer);

            int i;
            char expDate[] = new char[10];

            //Get today's date
            Date date = new Date();
            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            int year = cal.get(Calendar.YEAR);
            int month = cal.get(Calendar.MONTH) +1;
            int day = cal.get(Calendar.DAY_OF_MONTH);
            System.out.println("year = "+year+" month = "+month+" day= "+day);

            //Check expiry date
            try{

                //Get expiry date
                for(i=0; i<10; i++){
                    expDate[i] = contents.charAt(i);
                };
                    
                String expDateStr = new String(expDate);
                String delimiter = "-";
                String expDateArray[] = expDateStr.split(delimiter);

                int expYear = Integer.parseInt(expDateArray[0]);
                int expMonth = Integer.parseInt(expDateArray[1]);
                int expDay = Integer.parseInt(expDateArray[2]);

                if(year > expYear){
                    System.out.println("License invalid: Expired!");
                }
                else if(month > expMonth){
                    System.out.println("License invalid: Expired!");
                }
                else if(day > expDay){
                    System.out.println("License invalid: Expired!");
                }
                
                System.out.println("breakin... ");
                    
                    
            } catch (Exception e){
                System.err.println("Caught exception " + e.toString());
                   
            }
            

            //Generate signature
            byte[] realSig = dsa.sign();

            //Save signature in file
            FileOutputStream sigfos = new FileOutputStream("sig");
            sigfos.write(realSig);
            sigfos.close();

            ///Save public key in file 
            byte[] key = pub.getEncoded();
            FileOutputStream keyfos = new FileOutputStream("pubkey");
            keyfos.write(key);
            keyfos.close();

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }


        try{
            /*** Generate a DSA signature ***/
            String public_key = "pubkey";
            String sigFromLicense = "sig";

            //Get public key bytes
            FileInputStream keyfis = new FileInputStream(public_key);
            byte[] encKey = new byte[keyfis.available()];  
            keyfis.read(encKey);
            keyfis.close();

            //Get key specification
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);

            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            //Get signature bytes
            FileInputStream sigfis = new FileInputStream(sigFromLicense);
            byte[] sigToVerify = new byte[sigfis.available()]; 
            sigfis.read(sigToVerify);
            sigfis.close();

            //Get and initialize signature algorithm used to generate the sig
            Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
            sig.initVerify(pubKey);

            //Supply signature object with file data
            FileInputStream datafis = new FileInputStream(license);
            BufferedInputStream bufin = new BufferedInputStream(datafis);

            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                sig.update(buffer, 0, len);
            };
            bufin.close();

            //Verify signature
            boolean verifies = sig.verify(sigToVerify);
            System.out.println("signature verifies: " + verifies);
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }

    }
}