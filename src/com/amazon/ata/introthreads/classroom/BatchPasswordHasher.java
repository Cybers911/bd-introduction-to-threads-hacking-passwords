package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Maps;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A class to hash a batch of passwords in a separate thread.
 */
//This class needs to be modified in order to to be able to run in a separate thread.
    //RUN CONCURRENTLY
    //1Be sure the class is immutable
    //2Make class final and thread-safe
    //3Make instance variable finals
    //4 Check constructors for reference parameters, make sure they are defensive copied
    //5Check any instance variable returned to be that they returned by reference, not by value.
    //6 Avoid any public setter methods.
    //B Make it RUNNABLE or a subclass Thread

//    private final List<String> passwords;
    //make a Runnable or subclass threads
    //We are implementing Runnable Interface instead extending Thread in case this needs to
    //be a subclass.
public final class BatchPasswordHasher implements Runnable {

    private final List<String> passwords;
    private final Map<String, String> passwordToHashes;
    private final String salt;
    // the constructor receices a list of passwords to hash and the salt value.
    // The constructor initializes an empty map and the instance variables.
    // we need to receive a reference and not an object to a List, defensive Copy to instance variables.

    public BatchPasswordHasher(List<String> passwords, String salt) {
        //*this.passwords = passwords; Replace it with a defensive copy
        this.passwords = new ArrayList<>(passwords); //defensive copy
        this.salt = salt;
        passwordToHashes = new HashMap<>();
    }

    /**
     *  Hashes all of the passwords, and stores the hashes in the passwordToHashes Map.
     */

    // Lo que hace el siguiente metodo es dividir la lista de passwords en partes
    // y luego crear un hilo para cada parte.    Luego espera a que todos los hilos terminen
    // para unir los resultados en un solo mapa.

    public void hashPasswords() {
        try {
            for (String password : passwords) {
                final String hash = PasswordUtil.hash(password, salt);
                passwordToHashes.put(password, hash);
            }
            System.out.println(String.format("Completed hashing batch of %d passwords.", passwords.size()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a map where the key is a plain text password and the key is the hashed version of the plaintext password
     * and the class' salt value.
     *
     * @return passwordToHashes - a map of passwords to their hash value.
     */
    // Since we return a reference to an instance variable, we should defensive returned
    public Map<String, String> getPasswordToHashes() {
        Map<String, String> newMap = new HashMap<>(); //defensive copy
        newMap.putAll(passwordToHashes); //defensive copy to new map.  We return a new map
        // to avoid modifying the original.  We don't need to lock this map because
        // it's not shared with other threads.  We can return a reference to it.
        // This is thread-safe.  The map itself is not thread-safe.
        // But we can't modify it because we're returning a reference to it.
        // So, the map is thread-safe
        return passwordToHashes;
    }


    //This method is required by the Rnnable Inteface
    //The run() method run what is run on the process on the thread
    //Like main() in Java or handleRequest for lambda AWS
    @Override
    public void run() {
        this.hashPasswords();// Call our hashPasswords method to hash the passwords
                                //this method will be executed in a separate thread.
    }//now this class can be run concurrently in multiple threads
    //And it will hash passwords in parallel.
    //Note: The main thread will not wait for this thread to finish.
    //The main thread will continue executing other tasks.
    //This is a simple example of how to run a class concurrently.
    //This class can be used in a multithreaded environment.

}
