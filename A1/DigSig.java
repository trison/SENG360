import java.io.*;
import java.security.*;
import java.util.*;

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

            //Get expiry date from file
            int i;
            char expDate[] = new char[10];
            String expiry = "expiry: ";
            boolean dateFound=false;

            //today's date
            Date date = new Date();
            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            int year = cal.get(Calendar.YEAR);
            int month = cal.get(Calendar.MONTH) +1;
            int day = cal.get(Calendar.DAY_OF_MONTH);
            System.out.println("year = "+year+" month = "+month+" day= "+day);

            for(i=0; i<contents.length(); i++){
                try{

                    //get expiry date
                    if(i<10){
                        System.out.println("cool! char="+contents.charAt(i));
                        expDate[i] = contents.charAt(i);
                    }
                    else{
                        String expDateStr = new String(expDate);
                        String delimiter = "-";
                        String expDateArray[] = expDateStr.split(delimiter);

                        int expYear = Integer.parseInt(expDateArray[0]);
                        int expMonth = Integer.parseInt(expDateArray[1]);
                        int expDay = Integer.parseInt(expDateArray[2]);

                        if(year > expYear){
                            System.out.println("Your license had expired!");
                        }
                        else if(month > expMonth){
                            System.out.println("Your license had expired!");
                        }
                        else if(day > expDay){
                            System.out.println("Your license had expired!");
                        }
                        
                        System.out.println("breakin... ");
                        break;
                    }
                } catch (Exception e){
                    System.err.println("Caught exception " + e.toString());
                    break;
                }
            };

            //Generate signature
            byte[] realSig = dsa.sign();

            //Save signature and public key in files
            FileOutputStream sigfos = new FileOutputStream("sig");
            sigfos.write(realSig);
            sigfos.close();

            ///Save the public key in a file 
            byte[] key = pub.getEncoded();
            FileOutputStream keyfos = new FileOutputStream("pubkey");
            keyfos.write(key);
            keyfos.close();

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
}