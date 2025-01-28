package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Multimap;

import java.util.List;
import java.util.Map;

/**
 * App used to crack passwords.
 */
public class PasswordCracker {

    /**
     * Main method that generates hashes for common passwords and checkes the
     * hacked databases for any users
     * using these common passwords. Prints out any cracked passwords for the users in the database.
     */
    public static void main(String[] args) throws InterruptedException {

        long startTime = System.currentTimeMillis();

        // Read common passwords and generate hashes for them
        // Generate hashes for all passwords in the common passwords list
        // Write the hashes and passwords to a file
        // Read the hacked database and find users who have used the common passwords
        // Print out the cracked passwords for the users in the database
        // Print the total number of users and the total time elapsed to crack the passwords
        // Note: Passwords and hashes are loaded from files using PasswordUtil.java,
        // and the hacked database is read using PasswordUtil.java

        // Note: Passwords are loaded from a file called common-passwords.txt in this example,
        // but you can replace it with your own list of common passwords.
        //List of password to hash loaded from a filed called PasswordUtil.java

        final List<String> commonPasswords = PasswordUtil.readCommonPasswords();

        // Generate hashes for all passwords in the common passwords list
        // Write the hashes and passwords to a file
        // Read the hacked database and find users who have used the common passwords
        // Print out the cracked passwords for the users in the database
        // Print the total number of users and the total time elapsed to crack the passwords
        //Call generatAllHashes and writePasswordsAndHashes methods in PasswordHasher.java

        //Call generateAll Hashes in the passwordHasher in the list of passeords list
        final Map<String, String> passwordToHashes = PasswordHasher.generateAllHashes(commonPasswords);

        PasswordHasher.writePasswordsAndHashes(passwordToHashes);

        final Multimap<String, String> hackedHashToUserIds = PasswordUtil.readHackedDatabase();

        int count = 0;
        for (Map.Entry<String, String> passwordToHash : passwordToHashes.entrySet()) {
            final String password = passwordToHash.getKey();
            final String hash = passwordToHash.getValue();

            if (hackedHashToUserIds.containsKey(hash)) {
                count += hackedHashToUserIds.get(hash).size();
                System.out.println(String.format("Users %s are using the password %s", hackedHashToUserIds.get(hash), password));
            }
        }

        System.out.println(String.format("We found the password for %d users", count));
        System.out.println("Total time elapsed: " + (System.currentTimeMillis() - startTime) + " milleseconds");
    }
}
