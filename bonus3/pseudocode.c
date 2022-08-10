#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int             index;
    unsigned int    ret;
    char            buffer[132];
    FILE            *stream;

    stream = fopen("/home/user/end/.pass", "r");

    memset(buffer, '\0', 132);

    if (stream == NULL || argc != 2)
        ret = -1;
    else
    {
        fread(buffer, 1, 66, stream);

        index = atoi(argv[1]);

        buffer[index] = '\0';

        fread(&buffer[66], 1, 65, stream);

        fclose(stream);

        if (!strcmp(buffer, argv[1]))
            execl("/bin/sh", "sh", 0);
        else
            puts(&buffer[66]);
        ret = 0;
    }

    return (ret);

}
