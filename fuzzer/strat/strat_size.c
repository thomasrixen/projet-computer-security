#include "../help.h"
#include "../fuzzer.h"


static int strat_nasty_size(const char* target)
{
    static int crash_count = 0;


    // Liste de toutes les valeurs "values"
    const char* values[] = {
        "77777777777", // Max octal
        "99999999999", // Invalid octal
        "00000000000", // Zero
        "-0000000001", // Negative
        "18446744073", // Overflow 64-bit
        "21474836480",  // Large number
        "511",
        "1025",
        "513",
        "1023",
    };
    int count = sizeof(values)/sizeof(values[0]);

    // Modifier un seul élément
    for (int i = 0; i < count; i++) {
        
        struct tar_t header;
        init_base_header(&header);

        const char* test = values[i];

        memset(header.size, 0, sizeof(header.size));
        memcpy(header.size, test, 12);

        calculate_checksum(&header);

        write_tar("archive.tar", &header);

        // Lancer le test et sauvegarder le crash
        if (run_target(target) == 1) {
            char crash_name[PATH_MAX];
            /* store crashes in crashes/ */
            snprintf(crash_name, sizeof(crash_name), "crashes/crash_size_%d.tar", crash_count);
            if (rename("archive.tar", crash_name) != 0) {
                perror("rename crash file");
            } else {
                printf("CRASH -> %s\n", crash_name);
                crash_count++;
            }
        }
    }
    return crash_count;
}