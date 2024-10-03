#ifndef HELLO_H
#define HELLO_H

struct data_t
{
    int pid;
    int uid;
    char command[16];
    char message[12];
    char path[16];
};

#endif // HELLO_H