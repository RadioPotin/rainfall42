#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    char            buffer[40];
    int             i;

    i = atoi(argv[1]);

    if (i <= 9)
    {
        memcpy(buffer, argv[2], i * 4);

        if (i == 1464814662)
            execl("/bin/sh", "sh", 0);

        return (0);

    }

    return (1);
}

// HIGH
// ^
// | * ~       char *argv[] |               + 8 bytes
// | * ~          int argc  |               + 4 bytes
// | * ~     return address |               + 4 bytes
// | <-- EBP
// | * ~    unsigned int i  |               + 4 bytes
// | * ~   char buffer[40]  | ( 4 + 40 )    + 44 bytes
// | <-- ESP                | -> Total      = 64 bytes
// |
// ...
// |
// LOW
