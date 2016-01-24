/*
 *
 * Author: 93aef0ce4dd141ece6f5
 * Description: Simple scan-time crypter using
 * 				XOR to obfuscate a binary
 *
 * GCC compile command:
 * gcc -Wall -Werror -o crypt crypt.c
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * error handling
 * errno variable defines
 * error
 */
#include <errno.h>

/*
 * execve() used for 
 * executing the decrypted
 * file
 */
#include <unistd.h>

/*
 * defining linux-environment-
 * only instructions
 * include sys/stat header
 * for chmod function to
 * allow decrypted file to
 * be executable
 * CHMOD(x) macro to replace
 * all instances of it with
 * proper chmod function
 * x parameter will transfer
 * over from macro to function
 */
#ifdef __linux__
#include <sys/stat.h>

#define CHMOD(x) chmod((x), S_IRWXU)

#define USE_CHMOD
#endif

/*
 * options for crypting method
 * SINGLE_KEY is less effective
 * MULTI_KEY creates better obfuscation
 */
//#define SINGLE_KEY
#define MULTI_KEY

#define DEBUG

/*
 * definitions for crypting
 * or decrypting
 */
#define JOB_CRYPT 1
#define JOB_DECRYPT 2

/*
 * key for SINGLE_KEY mode
 * change to your desire
 */
#define XOR_KEY 0x01

/*
 * keys for MULTI_KEY mode
 * change to your desire
 * extend, change values, etc.
 */
#ifdef MULTI_KEY
unsigned char key[] = {0x03, 0x12, 0x4d, 0xe3, 0x11, 0x6f};
#endif

/*
 * struct to manage input and
 * output file handles
 */
typedef struct _files {
    FILE *infile;
    FILE *outfile;
} Files, *pFiles;

/*
 * function for error handling
 */
void fatal (char *s) {
#ifdef DEBUG
    fprintf (stderr, "[!] %s error: %s\n", s, strerror (errno));
#endif
    exit (EXIT_FAILURE);
}

/*
 * print program usage
 */
void printUsage (char *prog) {
    fprintf (stderr, "Usage: %s -j [JOB MODE] -f [IN FILE] -o [OUT FILE]\n"
                    "\t-j [JOB MODE] : Crypt/Decrypt\n"
                    "\t-f [IN FILE]  : File on which the job is to be done\n"
                    "\t-o [OUT FILE] : Output file\n", prog);
}

/*
 * function to initialize file struct
 */
pFiles newFile (void) {
    pFiles f = malloc (sizeof (*f));
    if (f == NULL) {
        return f;
    }

    f->infile = NULL;
    f->outfile = NULL;

    return f;
}

/*
 * function to de/crypt file
 */
int runJob (pFiles f) {
    int c, i;

    /*
     * read and XOR each character
     * one-by-one until the end 
     */
    for (c = fgetc (f->infile), i = 0; c != EOF; i++, c = fgetc (f->infile)) {
        #ifdef MULTI_KEY
        fputc (c^key[i % sizeof (key)], f->outfile);
        #elif SINGLE_KEY
        fputc (c^XOR_KEY, f->outfile);
        #endif
    }

    /*
     * return the number of bytes
     * read from the in file
     */
    return i;
}

int main (int argc, char *argv[]) {
    if (argc <= 1) {
        printUsage (argv[0]);
        exit (EXIT_FAILURE);
    }

    pFiles files = newFile();
    if (files == NULL) {
        fatal ("Initialise files struct");
    }

    /*
     * parse options from command line
     */
    int opt, jobflag = 0;
    char *ofile = NULL;
    while ((opt = getopt (argc, argv, "j:f:o:")) != -1) {
        switch (opt) {
            case 'j':
                if (strcmp (optarg, "crypt") == 0) {
                    jobflag = JOB_CRYPT;
                } else if (strcmp (optarg, "decrypt") == 0) {
                    jobflag = JOB_DECRYPT;
                } else {
                    #ifdef DEBUG
                    fprintf (stderr, "[!] Job error: Please select a suitable job\n");
                    #endif
                    free (files);
                    exit (EXIT_FAILURE);
                }
                break;
            case 'f':
                files->infile = fopen (optarg, "rb");
                if (files->infile == NULL) {
                    free (files);
                    fatal ("Infile");
                }
                break;
            case 'o':
                ofile = optarg;
                files->outfile = fopen (optarg, "wb");
                if (files->outfile == NULL) {
                    free (files);
                    fatal ("Outfile");
                }
                break;
            default:
                printUsage (argv[0]);
                free (files);
                exit (EXIT_FAILURE);
        }
    }

    /*
     * de/crypt file
     */
    runJob (files);

    /*
     * clean up handles and free heap
     */
    fclose (files->infile);
    fclose (files->outfile);

    free (files);

    /*
     * if decrypting job, run the 
     * program when finished
     */
    if (jobflag == JOB_DECRYPT) {
        char *args[] = {ofile, NULL};

        #ifdef USE_CHMOD
        CHMOD (ofile);
        #endif

        int err = execve (args[0], args, NULL);
        if (err == -1) {
            fatal ("Execute file");
        }
    }

    return EXIT_SUCCESS;
}
