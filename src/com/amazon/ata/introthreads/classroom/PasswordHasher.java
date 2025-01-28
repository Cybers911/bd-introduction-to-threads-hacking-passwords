package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A class to pre-compute hashes for all common passwords to speed up cracking the hacked database.
 *
 * Passwords are downloaded from https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials
 */
public class PasswordHasher {
    // should create the file in your workspace directory
    private static final String PASSWORDS_AND_HASHES_FILE = "./passwordsAndHashesOutput.csv";
    private static final String DISCOVERED_SALT = "salt";
// A salt is a value inclued in the hashing/encryped to make it to de-hash de crypt the values.
    //Normally a salt is a long string, of random values, 64,128,512,768 bytes, characters, salt are commons.
    /**
     * Generates hashes for all of the given passwords.
     *
     * @param passwords List of passwords to hash
     * @return map of password to hash
     * @throws InterruptedException
     */

    //Lo que hace la siguiente funcion es generar hashes para todos los passwords comunes

    /**Certainly! Let's break down the `generateAllHashes` method:

     ```java
     public static Map<String, String> generateAllHashes(List<String> passwords) throws InterruptedException {
     Map<String, String> passwordToHashes = Maps.newConcurrentMap();
     BatchPasswordHasher batchHasher = new BatchPasswordHasher(passwords, DISCOVERED_SALT);
     batchHasher.hashPasswords();
     passwordToHashes.putAll(batchHasher.getPasswordToHashes());

     return passwordToHashes;
     }
     ```

     This method is responsible for generating hashes for a list of passwords. Here's what each line does:

     1. The method takes a `List<String>` of passwords as input and returns a `Map<String, String>` where the keys are passwords and the values are their corresponding hashes.

     2. `Map<String, String> passwordToHashes = Maps.newConcurrentMap();`
     This creates a new concurrent map to store the password-hash pairs. A concurrent map is used to ensure thread-safety if multiple threads access this map simultaneously.

     3. `BatchPasswordHasher batchHasher = new BatchPasswordHasher(passwords, DISCOVERED_SALT);`
     This creates a new `BatchPasswordHasher` object, passing in the list of passwords and a predefined salt (`DISCOVERED_SALT`). The salt is used in the hashing process to add an extra layer of security.

     4. `batchHasher.hashPasswords();`
     This calls the `hashPasswords()` method on the `BatchPasswordHasher` object, which presumably performs the actual hashing of the passwords.

     5. `passwordToHashes.putAll(batchHasher.getPasswordToHashes());`
     After hashing is complete, this line retrieves the password-hash pairs from the `BatchPasswordHasher` and adds them all to the `passwordToHashes` map.

     6. `return passwordToHashes;`
     Finally, the method returns the map containing all the password-hash pairs.

     Currently, this method is not utilizing multiple threads as it's using a single `BatchPasswordHasher`. To optimize this for multi-threading, you would need to split the password list into multiple batches and process each batch with a separate thread.
     * */

     /** @param passwords
     * @return
     * @throws InterruptedException
     */

    public static Map<String, String> generateAllHashes(List<String> passwords) throws InterruptedException {
        //This map will hold the result of all hashes in parallel passwords in parallel

        Map<String, String> passwordToHashes = Maps.newConcurrentMap();
        //replace from a single BatchPasswordHasher to multiple threads concurrent call
       // BatchPasswordHasher batchHasher = new BatchPasswordHasher(passwords, DISCOVERED_SALT);
        //batchHasher.hashPasswords();
       // passwordToHashes.putAll(batchHasher.getPasswordToHashes());


        //Splist the list of passwords into batches sublists to give to each thread(We will have 4 threads)

        List<List<String>> passwordSublists = Lists.partition(passwords, passwords.size() / 4);

        // Since the hashed passwords a erinside the BatchPasswordHashes
        // And the BatchPasswordHasher will be destroyed when the thread completes
        //We will store and save each BatchPasswordHasher's password-hash pairs into our map So will exist
        // When the main thread is done, it will wait for all threads to finish using waitForThreadsToComplete()
        // So we copy the hashed passwords to our final sets of hashed passwords

        List<BatchPasswordHasher> savedHashers = Lists.newArrayList();

        //Since a thread is destroyed when is done and we need for all thread to be completed
        //before we can merge the results, we will sotre save the thead so we can reference them in the
        // waitForThreadsToComplete() method
        List<Thread> threads = Lists.newArrayList();

        // Loop over the sublists and create a thread for each sublist
        // Loop for each sublists of passwords and start a BatchPasswordHasher thread for each one

        //Loop over the sublists and create a thread for each sublist
        //Loop for each sublists of passwords and start a BatchPasswordHasher thread for each one

        for (int i = 0; i < passwordSublists.size(); i++) {
            // instantiate a new BatchPasswordHasher for each sublist and the salt value (salt)
            BatchPasswordHasher aHasher = new BatchPasswordHasher(passwordSublists.get(i), DISCOVERED_SALT);

            // saves the new BatchPasswordHasher to our list of saved hashers so we can
            // access when the thread is done
            savedHashers.add(aHasher);

            // Create and start a new thread for the BatchPasswordHasher
            // We use a thread pool to avoid creating a new thread for each password
            // and to manage the threads efficiently
            // This will also help us manage resources better
            ExecutorService executor = Executors.newFixedThreadPool(4);
            executor.submit(aHasher);
            executor.shutdown();

            // Wait for the thread to finish, so we can add it to our list of threads
            // If the thread is not finished yet, this call will block until it is
            // This is useful if we want to wait for all threads to finish before proceeding
            // with the main thread
            //executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
            // Instantiate a thread for the new BatchPasswordHasher
            Thread aThread = new Thread(aHasher);
            //Save the thread to our list of threads in a list so we can send to waitForThreadsToComplete()
            threads.add(aThread);
            // Start the thread
            aThread.start();// exectution of this process continuew, we dont wait for the process to finish
            // After the thread has finished, we add it to our list of threads
            

        }

        // Now that all threads has been started well them to complete
        waitForThreadsToComplete(threads);

        //So now all the thread are completed each BatchPasswordHasher has hashed its passwords
        //Merge the hashed passwords from all threads into our final map of hashed passwords from each
        //BatchPasswordHasher into the final map of hashed passwords resultult

        for (BatchPasswordHasher aHasher : savedHashers) {
            passwordToHashes.putAll(aHasher.getPasswordToHashes());//copy all hashed passwords
            // from aHasher to our final map result
        }

        // Once all threads have finished, we can add all the hashed passwords from the saved hashers
        // to our final map of hashed passwords

        for (BatchPasswordHasher savedHasher : savedHashers) {
            passwordToHashes.putAll(savedHasher.getPasswordToHashes());
        }

        // Write the pairs of password and its hash to a file
        writePasswordsAndHashes(passwordToHashes);

        // Return the final map of hashed passwords

        return passwordToHashes;
    }

    /**
     * Makes the thread calling this method wait until passed in threads are done executing before proceeding.
     *
     * @param threads to wait on
     * @throws InterruptedException
     */
    public static void waitForThreadsToComplete(List<Thread> threads) throws InterruptedException {
        for (Thread thread : threads) {//Loop over all threads passed asa parameter
            thread.join();//Wait for the current thread to finish
        }
    }

    /**
     * Writes pairs of password and its hash to a file.
     */
    static void writePasswordsAndHashes(Map<String, String> passwordToHashes) {
        File file = new File(PASSWORDS_AND_HASHES_FILE);
        try (
            BufferedWriter writer = Files.newBufferedWriter(file.toPath());
            CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT)
        ) {
            for (Map.Entry<String, String> passwordToHash : passwordToHashes.entrySet()) {
                final String password = passwordToHash.getKey();
                final String hash = passwordToHash.getValue();

                csvPrinter.printRecord(password, hash);
            }
            System.out.println("Wrote output of batch hashing to " + file.getAbsolutePath());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
