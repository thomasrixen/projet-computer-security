#include "../help.h"
#include "../fuzzer.h"


static int strat_nasty_id(const char* target)
{
    static int crash_count = 0;


    // Liste de toutes les valeurs "values"
    const char* values[] = {
        "7777777",
        "9999999",
        "-000001",
        "2147483647",
        "0000000",
        "\0\0\0\0",
        "abcdefg"
    };
    int count = sizeof(values)/sizeof(values[0]);

    // Modifier un seul élément
    for (int i = 0; i < count; i++) {
        
        struct tar_t header;
        init_base_header(&header);

        const char* test = values[i];

        memset(header.uid, 0, sizeof(header.uid));
        memset(header.gid, 0, sizeof(header.gid));
        strcpy(header.uid, test);
        strcpy(header.gid, test);

        calculate_checksum(&header);

        write_tar("archive.tar", &header);

        // Lancer le test et sauvegarder le crash
        if (run_target(target) == 1) {
            char crash_name[PATH_MAX];
            /* store crashes in crashes/ */
            snprintf(crash_name, sizeof(crash_name), "crashes/crash_id_%d.tar", test);
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