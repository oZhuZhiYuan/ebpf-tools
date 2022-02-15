#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[])
{
     char s[] = "abcd";
     s[3] = 0x21;
     printf("%s",s); 
     return 0;
}
