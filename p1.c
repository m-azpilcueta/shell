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
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include "list.h"

#define MAX 1024

tHist hist;
int rec_counter = 0;

struct CMD {
    char *name;
    void (*pf) (int, char **);
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
    {"borrar", "borrar [name1 name2 ..]    Delete files or empty directories"},
    {"borrarrec", "borrarrec [name1 name2 ..]   Delete files or non empty directories"},
    {"listfich", "listfich [-long][-link][-acc] n1 n2 ..	List files"},
    {NULL, NULL}
};

int chop_input(char *cadena, char *trozos[]);
void process_input(int chop_number, char *chops[]);

void cmd_autores(int chop_number, char *chops[]) {
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

void cmd_pid(int chop_number, char *chops[]) {
    if (chops[0] == NULL) {
        pid_t pid = getpid();
        printf("Shell pid: %d\n", pid);
    } else if (strcmp(chops[0], "-p") == 0) {
        pid_t ppid = getppid();
        printf("Shell's parent process pid: %d\n", ppid);
    }
}

void curr_dir() {
    char dir[MAX];
    if (getcwd(dir, sizeof(dir)) != NULL) {
        printf("%s\n", dir);
    } else {
        perror("Cannot return directory");
    }    
}

void cmd_carpeta(int chop_number, char *chops[]) {
    if (chops[0] == NULL) {
        curr_dir();
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

void cmd_fecha(int chop_number, char *chops[]) {
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

void cmd_hist(int chop_number, char *chops[]) {
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

void cmd_comando(int chop_number, char *chops[]) {
    long cmd_number;
    int cmd_int, args_number = 0;
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
        args_number = chop_input(command_cpy, cmd_chops);
        process_input(args_number, cmd_chops);   
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

void cmd_ayuda(int chop_number, char *chops[]) {
    if (chops[0] == NULL) {
        printf("'ayuda cmd' where cmd is one of the following commands:\n"
        "fin salir bye fecha pid autores hist comando carpeta infosis ayuda crear borrar borrarrec listfich\n");
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

char LetraTF(mode_t m) {
    switch (m & S_IFMT) {
        /*and bit a bit con los bits de formato,0170000 */
    case S_IFSOCK:
        return 's'; /*socket */
    case S_IFLNK:
        return 'l'; /*symbolic link*/
    case S_IFREG:
        return '-'; /* fichero normal*/
    case S_IFBLK:
        return 'b'; /*block device*/
    case S_IFDIR:
        return 'd'; /*directorio */
    case S_IFCHR:
        return 'c'; /*char  device*/
    case S_IFIFO:
        return 'p'; /*pipe*/
    default:
        return '?'; /*desconocido, no deberia aparecer*/
    }
}

char *ConvierteModo(mode_t m, char * permisos) {
    strcpy(permisos, "---------- ");
    permisos[0] = LetraTF(m);
    if (m & S_IRUSR) permisos[1] = 'r'; /*propietario*/
    if (m & S_IWUSR) permisos[2] = 'w';
    if (m & S_IXUSR) permisos[3] = 'x';
    if (m & S_IRGRP) permisos[4] = 'r'; /*grupo*/
    if (m & S_IWGRP) permisos[5] = 'w';
    if (m & S_IXGRP) permisos[6] = 'x';
    if (m & S_IROTH) permisos[7] = 'r'; /*resto*/
    if (m & S_IWOTH) permisos[8] = 'w';
    if (m & S_IXOTH) permisos[9] = 'x';
    if (m & S_ISUID) permisos[3] = 's'; /*setuid, setgid y stickybit*/
    if (m & S_ISGID) permisos[6] = 's';
    if (m & S_ISVTX) permisos[9] = 't';
    return permisos;
}

void cmd_crear(int chop_number, char *chops[]) {
    int fd;

    if (chops[0] == NULL) {
        curr_dir();
        return;
    } else {
        if (strcmp(chops[0], "-f") == 0) {
            if ((fd = open(chops[1], O_CREAT | O_EXCL, 0744)) == -1) {
                perror("Cannot create file");
                return;
            } else close(fd);
        } else if (strcmp(chops[0], "-f") != 0) {
            if ((mkdir(chops[0], 0744) == -1)) {
                perror("Cannot create directory");
                return;
            }
        }
    } 
}

void delete(char *tr, int rec){
    struct stat pt;
    DIR *dir;
    struct dirent *entry;
    char todo[MAX] = "";

    if (lstat(tr, &pt) == -1) {
        perror("Cannot delete");
        return;
    } else {
        if (!((pt.st_mode & S_IFMT) == S_IFDIR)) {
            if (unlink(tr) == -1) {
                perror("Cannot delete file");
            }
            return;
        } else {
            if (rec) {
                dir = opendir(tr);
                strcpy(todo, tr);
                while((entry = readdir(dir)) != NULL) {
                    if (entry -> d_name[0] == '.') continue;
                    strcpy(todo, tr);
                    strcat(todo, "/");
                    strcat(todo, entry->d_name);
                    delete(todo, 1);
                }
                closedir(dir);
                delete(tr, 0);
            } else {
                if (rmdir(tr) == -1) {
                    perror("Cannot delete directory");
                    return;
                }
            }
        }
    }
}

void cmd_borrar(int chop_number, char * chops[]){
    int i = 0;

    if (chops[0] == NULL) {
        curr_dir();
        return;
    } else {
        while (chops[i] != NULL){
            delete(chops[i], 0);
            i++;
        }
    }
}

void cmd_borrarrec(int chop_number, char *chops[]) {
    int it = 0;

    if (chops[0] == NULL) {
        curr_dir();
        return;
    } else {
        while (chops[it] != NULL) {
            delete(chops[it], 1);
            it++;
        }    
    }
}

char *get_info(char *data, int link, int acc, char *path) {
    struct stat pt;
    time_t modif_time;
    struct passwd *passwd;
    struct group *group;
    char builder[MAX];

    if (lstat(path, &pt) == -1) {
        perror("Cannot stat");
    } else {
        if (acc) modif_time = pt.st_atime;
        else modif_time = pt.st_mtime;
        strftime(data, sizeof(builder), "%Y/%m/%d-%H:%M ", localtime(&modif_time));
        sprintf(builder, "%d ", (int) pt.st_nlink);
        strcat(data, builder);
        sprintf(builder, "(%ld) ", (unsigned long) pt.st_ino);
		strcat(data,builder);
        passwd = getpwuid(pt.st_uid);
		sprintf(builder, "%s ", passwd->pw_name);
		strcat(data, builder);
        group = getgrgid(pt.st_gid);
		sprintf(builder, "%s ", group->gr_name);
		strcat(data, builder);
        sprintf(builder, "%s ", ConvierteModo(pt.st_mode, builder));
		strcat(data, builder);
        sprintf(builder, "%d ", (signed int) pt.st_size);
		strcat(data, builder);
        strcat(data, strrchr(path, '/') + 1);
        if (S_ISLNK (pt.st_mode) && link){
            readlink(path, builder, pt.st_size);
            builder[pt.st_size] = '\0';
            strcat(data, "->");
            strcat(data, builder);
        }
    }
    return data;
}

void listar(int longL, int link, int acc, char *path) {
    struct stat pt;
    char data[MAX];

    if (lstat(path, &pt) == -1) {
        perror("Cannot stat");
        return;
    } else {
        if (longL) {
            printf("%s\n", get_info(data, link, acc, path)); 
        } else {
            sprintf(data, "%d ", (signed int) pt.st_size);
            strcat(data, strrchr(path, '/') + 1);
            printf("%s\n", data);
        }
    } 
}

void cmd_listfich(int chop_number, char *chops[]){
    int longL = 0, link = 0, acc = 0, flags = 0;
    char path[MAX];

    if (chops[0] == NULL) {
        curr_dir();
        return;
    } else {
        for (int i = 0; chops[i] != NULL; i++) {
            if (strcmp(chops[i], "-long") == 0){
                longL = 1;
                flags++;
            } else if (strcmp(chops[i], "-link") == 0) {
                link = 1;
                flags++;
            } else if (strcmp(chops[i], "-acc") == 0) {
                acc = 1;
                flags++;
            } else break;
        }

        if (flags == chop_number) {
            curr_dir();
            return;
        }

        for (int i = flags; i < chop_number; i++) {
            strcpy(path, chops[i]);
            if (strncmp(chops[i], "/", 1) != 0 && strncmp(chops[i], "./", 2) != 0 && strncmp(chops[i], "../", 3) != 0) {
                strcpy(path, "./");
                strcat(path, chops[i]);
            } else {
                strcpy(path, chops[i]);
            }
            listar(longL, link, acc, path);
        }
    }
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
    {"borrar", cmd_borrar},
    {"borrarrec", cmd_borrarrec},
    {"listfich", cmd_listfich},
    {NULL, NULL}
};

int chop_input(char *cadena, char *trozos[]) {
    int i = 1;
    if ((trozos[0] = strtok(cadena, " \n\t")) == NULL) return 0;
    while ((trozos[i] = strtok(NULL, " \n\t")) != NULL) i++;
    return i;
}

void process_input(int chop_number, char *chops[]) {
    for (int i = 0; c[i].name != NULL; i++) {
        if(strcmp(chops[0], c[i].name) == 0) {
            (*c[i].pf)(chop_number - 1, chops + 1);
            return;
        }
    }
    printf("Command '%s' not found\n", chops[0]);
}

int main() {
    char user_input[MAX];
    char *chops[MAX/2];
    int chop_number = 0;

    createEmptyHistory(&hist);
    while (1) {
        printf(">> ");
        fgets(user_input, MAX, stdin);
        if (user_input[0] != '\n') {
            insertHistory(user_input, &hist);
            chop_number = chop_input(user_input, chops);
            process_input(chop_number, chops);
        }
    }

    deleteHistory(&hist);
    return 0;
}