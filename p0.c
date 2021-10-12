/*
    Daniel Ferreiro Villamor: d.ferreiro
    Martín Azpilcueta Rabuñal: m.azpilcueta
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <time.h>
#include "list.h"

#define MAX 1024

tHist hist;
int rec_counter = 0;

struct CMD {
    char *name;
    void (*pf) (char **);
};

struct ayuda {
    char *command;
    char *description;
};

struct ayuda a[] = {
    {"autores", "autores [-n|-l]	Show the names and logins of the authors"},
    {"pid", "pid [-p]	Show the pid of this shell or from its parent process"},
    {"carpeta", "carpeta [dir]	Change (or show) the current directory of the shell"},
    {"fecha", "fecha [-d|-h]	Show the date and/or the current time"},
    {"hist", "hist [-c|-N]	Show the historic of commands, use -c to delete it"},
    {"comando", "comando [-N]	Repeat command N (from the historic)"},
    {"infosis", "infosis 	Show information about the machine where the shell is running"},
    {"ayuda", "ayuda [cmd]	Shows help about commands"},
    {"fin", "fin 	Terminates the shell execution"},
    {"salir", "salir 	Terminates the shell execution"},
    {"bye", "bye 	Terminates the shell execution"},
    {"crear", "crear [-f] [name]    Creates a file or a directory"},
    {NULL, NULL}
};

int chop_input(char *cadena, char *trozos[]);
void process_input(char *chops[]);

void cmd_autores(char *chops[]) {
    if (chops[0] == NULL) {
        printf("Daniel Ferreiro Villamor: d.ferreiro\n"
        "Martín Azpilcueta Rabuñal: m.azpilcueta\n");
    } else if (strcmp(chops[0], "-l") == 0) {
        printf("d.ferreiro\n"
        "m.azpilcueta\n");
    } else if (strcmp(chops[0], "-n") == 0) {
        printf("Daniel Ferreiro Villamor\n"
        "Martín Azpilcueta Rabuñal\n");
    }
}

void cmd_pid(char *chops[]) {
    if (chops[0] == NULL) {
        pid_t pid = getpid();
        printf("Shell pid: %d\n", pid);
    } else if (strcmp(chops[0], "-p") == 0) {
        pid_t ppid = getppid();
        printf("Shell's parent process pid: %d\n", ppid);
    }
}

void cmd_carpeta(char *chops[]) {
    if (chops[0] == NULL) {
        char dir[MAX];
        if (getcwd(dir, sizeof(dir)) != NULL) {
            printf("%s\n", dir);
        } else {
            perror("Cannot return directory");
        }
        return;
    }
    if (chdir(chops[0]) == -1) {
        perror("Cannot change directory");
    }
}

void solo_fecha() {
    time_t rawtime;
    struct tm *info;
    char buffer[11];

    time(&rawtime);
    info = localtime(&rawtime);

    strftime(buffer,sizeof(buffer),"%d/%m/%Y",info);
    printf("%s\n", buffer);
}

void solo_hora() {
    char *tr[8];

    time_t t;
    time(&t);
    chop_input(ctime(&t),tr);
    printf("%s\n",tr[3]);
}

void cmd_fecha(char *chops[]) {
    if (chops[0] == NULL) {
        solo_hora();
        solo_fecha();
    } else {
        if (strcmp(chops[0], "-d") == 0) {
            solo_fecha();
        } else if (strcmp(chops[0], "-h") == 0) {
            solo_hora();
        }
    }
}

void cmd_hist(char *chops[]) {
    int pos;

    if (isEmptyHistory(hist)) return;
    if (chops[0] == NULL) {
        showHistory(hist);
    } else {
        if (strcmp(chops[0], "-c") == 0) {
            deleteHistory(&hist);
        } else if (strncmp(chops[0], "-", 1) == 0) {
            pos = atoi(chops[0] + 1);
            if (pos == 0) return;
            if (pos > hist.last) {
                showHistory(hist);
                return;
            }
            showNHistory(pos, hist);
        }
    }    
}

void cmd_comando(char *chops[]) {
    long cmd_number;
    int cmd_int;
    char *remaining, *command, *cmd_chops[MAX/2], command_cpy[MAX];

    if (isEmptyHistory(hist)) return;
    if (chops[0] == NULL) {
        showHistory(hist);
        return;
    }
    cmd_number = strtol(chops[0], &remaining, 0);
    if (remaining == chops[0]) {
        printf("Invalid argument: only numbers are allowed\n");
        return;
    } else {
        cmd_int = (int) cmd_number; 
        if ((cmd_int < 0) | (cmd_int > hist.last)) {
            printf("There is no element %d in the historic\n", cmd_int);
            return;
        }   
        if (rec_counter >= 10) {
            rec_counter = 0;
            printf("Too many recursive calls\n");
            return;
        }
        command = getHistory(cmd_int, hist);
        strcpy(command_cpy, command);
        printf("Executing hist (%d): %s", cmd_int, command_cpy);
        rec_counter++;
        chop_input(command_cpy, cmd_chops);
        process_input(cmd_chops);   
        rec_counter = 0;
    }
}

void cmd_uname() {
    struct utsname uname_content;

    if (uname(&uname_content) != 0) {
        perror("Cannot uname");
    } else {
        printf("%s (%s), OS: %s%s%s\n", uname_content.nodename, uname_content.machine, uname_content.sysname, uname_content.release, uname_content.version);
    }
}

void cmd_ayuda(char *chops[]) {
    if (chops[0] == NULL) {
        printf("'ayuda cmd' where cmd is one of the following commands:\n"
        "fin salir bye fecha pid autores hist comando carpeta infosis ayuda crear\n");
    } else {
        for (int i = 0; a[i].command != NULL; i++) {
            if (strcmp(chops[0], a[i].command) == 0) {
                printf("%s\n", a[i].description);
                return;
            }
        }
        printf("%s not found\n", chops[0]);
    }
}

void cmd_bye() {
    deleteHistory(&hist);
    exit(0);
}

/* Lab Assignment 1 */

void cmd_crear(char *chops[]) {

}

struct CMD c[] = {
    {"autores", cmd_autores},
    {"pid", cmd_pid},
    {"carpeta", cmd_carpeta},
    {"fecha", cmd_fecha},
    {"hist", cmd_hist},
    {"comando", cmd_comando},
    {"infosis", cmd_uname},
    {"ayuda", cmd_ayuda},
    {"fin", cmd_bye},
    {"salir", cmd_bye},
    {"bye", cmd_bye},
    {"crear", cmd_crear},
    {NULL, NULL}
};

int chop_input(char *cadena, char *trozos[]) {
    int i = 1;
    if ((trozos[0] = strtok(cadena, " \n\t")) == NULL) return 0;
    while ((trozos[i] = strtok(NULL, " \n\t")) != NULL) i++;
    return i;
}

void process_input(char *chops[]) {
    for (int i = 0; c[i].name != NULL; i++) {
        if(strcmp(chops[0], c[i].name) == 0) {
            (*c[i].pf)(chops + 1);
            return;
        }
    }
    printf("Command '%s' not found\n", chops[0]);
}

int main() {
    char user_input[MAX];
    char *chops[MAX/2];

    createEmptyHistory(&hist);
    while (1) {
        printf(">> ");
        fgets(user_input, MAX, stdin);
        if (user_input[0] != '\n') {
            insertHistory(user_input, &hist);
            chop_input(user_input, chops);
            process_input(chops);
        }
    }

    deleteHistory(&hist);
    return 0;
}