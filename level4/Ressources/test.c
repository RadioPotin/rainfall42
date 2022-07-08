int main(int ac, char *argv[])
{
    int m;

    if (ac != 2)
        return 0;

    printf("%s%2$n", argv[1], &m);

    printf("\n%d\n", m);

    return 0;
}
