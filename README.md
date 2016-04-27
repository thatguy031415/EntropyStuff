# EntropyStuff


A couple of scripts that calculate the Shannon entropy of a file, or the Shannon entropy of PE file sections, and return a determination of whether the file or section likely packed/crypted.  Soon to be written into a module for the Viper framework.


Entropy.py calculates file entropy only.  Section_entropy.py calculates the section entropy of PE files.  Fsentropy.py determines whether the file is a PE, and if so, returns the file and section entropy; if not, it returns only the file entropy.
