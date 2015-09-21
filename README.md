# SENG360 Assignment 1

## Running program
Compile the file with 
>javac DigSig.java

Run the generated executable with
>java DigSig

## Design
Upon running, the program will look for a license.txt file. If not found, the program will
terminate with File Not Found exception.

If a license file exists, the program will generate and output a signature and public key.

The user is then able to continue with verification of the signature and license, or exit the program.

The license file contains the expiry date in format yyyy-mm-dd. If the current day is past the
expiry date, the program will exit with output message "License invalid: Expired!"

The user can alter the contents of the license before continuing with verification. If the license
file is changed, the program will exit with output message indicating the signature was invalid. If
the license was not changed, the program output message indicating a valid signature and continue executing.
Continuing execution entails the program notifying the user of how special they are.

