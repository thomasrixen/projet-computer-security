#include "../help.h"
#include "../fuzzer.h"


static int strat_nasty_name(const char* target)
{
    static int crash_count = 0;


    // Liste de toutes les valeurs "values"
    const char* values[] = {
        "../../../../../../../../etc/passwd",
        "\\x00\\x00\\x00",
        "\n\n\n\n",
        "\r\n\r\n",
        "\0",
        "",
        ".",
        "..",
        "/",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "%s%s%s%s",
        "%x%x%x%x",
        "%n%n%n%n",
        "%p%p%p%p",
        "test\0file",
        "\xFF\xFF\xFF",
        "\xFF",
        "\x80",
        "\x7F",
        "\x00\xFF\xAA",
    };
    int count = sizeof(values)/sizeof(values[0]);

    // Modifier un seul élément
    for (int i = 0; i < count; i++) {
        
        struct tar_t header;
        init_base_header(&header);

        const char* test = values[i];

        memset(header.name, 0, sizeof(header.name));
        strcpy(header.name, test);

        calculate_checksum(&header);

        write_tar("archive.tar", &header);

        // Lancer le test et sauvegarder le crash
        if (run_target(target) == 1) {
            char crash_name[PATH_MAX];
            /* store crashes in crashes/ */
            snprintf(crash_name, sizeof(crash_name), "crashes/crash_name_%d.tar", test);
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