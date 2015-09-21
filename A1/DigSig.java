/*--------
Signature generation and verification references Java doc - 
https://docs.oracle.com/javase/tutorial/security/apisign/index.html
---------*/

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.Scanner;

class DigSig {

    public static String getInput(){
        Scanner user_input = new Scanner( System.in );
        String in;
        System.out.println("Enter 1 to verify your license expiry and digital signature.");
        System.out.println("Enter any other key to exit.");
        System.out.print("Enter your choice now, human: ");
        in = user_input.nextLine();
        return in;
    }

    public static void main(String[] args) throws IOException{
        /*** Generate a DSA signature ***/
        String license = "license.txt";
        String line = null;
        boolean error=false;
        byte[] buffer = new byte[1024];

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

            int len;
            while ((len = bufin.read(buffer)) >= 0) {
                dsa.update(buffer, 0, len);
            };
            bufin.close();
            
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

            System.out.println("***\nHello human. A public key and signature has been generated from the license file.\n");
            System.out.println("This program will only continue to run once your license file is verified.\n***");

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
            error = true;
        }

        if(error){
            System.exit(0);
        }
        /*** User chooses to verify license ***/
        String choice;
        choice = getInput();

        /*** Verify License ***/
        if(choice.equals("1")){
            try{
                int i;
                char expDate[] = new char[10];
                String contents = new String(buffer);
                String public_key = "pubkey";
                String sigFromLicense = "sig";

                //Get today's date
                Date date = new Date();
                Calendar cal = Calendar.getInstance();
                cal.setTime(date);
                int year = cal.get(Calendar.YEAR);
                int month = cal.get(Calendar.MONTH) +1;
                int day = cal.get(Calendar.DAY_OF_MONTH);

                /*** Check expiry date ***/
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
                        
                /*** Verify DSA signature ***/
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

                buffer = new byte[1024];
                int len;
                while (bufin.available() != 0) {
                    len = bufin.read(buffer);
                    sig.update(buffer, 0, len);
                };
                bufin.close();

                //Verify signature
                boolean verifies = sig.verify(sigToVerify);
                if(verifies){
                    System.out.println("---\nSignature verified!\n---");
                    System.out.println("Human, you are ~ very ~ special.");
                }
                else{
                    System.out.println("---\nSorry human, the signature was unable to be verified.\n---");
                }
            } catch (Exception e) {
                System.err.println("Caught exception " + e.toString());
            }
        }
        else{
            System.out.println("~ Farewell human ~ ");
        }
    }//main
}//class