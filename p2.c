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
#include <errno.h>
#include "list.h"
#include "memlist.h"

#define MAX 1024

tHist hist;
tMemList memlist;
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
    {"listdir", "listdir [-reca] [-recb] [-hid][-long][-link][-acc] n1 n2 ..	List files inside directories"},
    {"malloc", "malloc [-free] tam      Allocates (or deallocates) memory in the program"},
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
               "fin salir bye fecha pid autores hist comando carpeta infosis ayuda crear borrar borrarrec listfich listdir "
               "recursiva e-s volcarmem llenarmem dealloc malloc mmap shared memoria\n");
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
    deleteMemlist(&memlist);
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
        if (strcmp(chops[0], "-f") == 0 && chop_number > 1) {
            if ((fd = open(chops[1], O_CREAT | O_EXCL, 0744)) == -1) {
                perror("Cannot create file");
                return;
            } else close(fd);
        } else if (strcmp(chops[0], "-f") != 0) {
            if ((mkdir(chops[0], 0744) == -1)) {
                perror("Cannot create directory");
                return;
            }
        } else curr_dir();
    } 
}

void delete(char *tr, int rec){
    struct stat pt;
    DIR *dir;
    struct dirent *entry;
    char it[MAX];

    if (lstat(tr, &pt) == -1) {
        printf("Cannot delete '%s': %s\n", tr, strerror(errno));
        return;
    } else {
        if (!((pt.st_mode & S_IFMT) == S_IFDIR)) {
            if (unlink(tr) == -1) {
                printf("Cannot delete file '%s': %s\n", tr, strerror(errno));
            }
            return;
        } else {
            if (rec) {
                if ((dir = opendir(tr)) == NULL) {
                    printf("Cannot delete directory '%s': %s\n", tr, strerror(errno));
                    return;
                } else {
                    while((entry = readdir(dir)) != NULL) {
                        if (entry -> d_name[0] == '.') continue;
                        strcpy(it, tr);
                        strcat(it, "/");
                        strcat(it, entry->d_name);
                        delete(it, 1);
                    }
                    closedir(dir);
                    delete(tr, 0);
                }
            } else {
                if (rmdir(tr) == -1) {
                    printf("Cannot delete directory '%s': %s\n", tr, strerror(errno));
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

char *get_info(struct stat pt, char *data, int link, int acc, char *path, char *fpath) {
    time_t modif_time;
    struct passwd *passwd;
    struct group *group;
    char builder[MAX];

    if (acc) modif_time = pt.st_atime;
    else modif_time = pt.st_mtime;
    strftime(data, sizeof(builder), "%Y/%m/%d-%H:%M ", localtime(&modif_time));
    sprintf(builder, "%3d ", (int) pt.st_nlink);
    strcat(data, builder);
    sprintf(builder, "(%8ld) ", (unsigned long) pt.st_ino);
    strcat(data,builder);
    passwd = getpwuid(pt.st_uid);
    sprintf(builder, "%16s ", passwd->pw_name);
    strcat(data, builder);
    group = getgrgid(pt.st_gid);
    sprintf(builder, "%16s ", group->gr_name);
    strcat(data, builder);
    sprintf(builder, "%10s ", ConvierteModo(pt.st_mode, builder));
    strcat(data, builder);
    sprintf(builder, "%9d ", (signed int) pt.st_size);
    strcat(data, builder);
    strcat(data, path);
    if (S_ISLNK (pt.st_mode) && link){
        readlink(fpath, builder, pt.st_size);
        builder[pt.st_size] = '\0';
        strcat(data, "->");
        strcat(data, builder);
    }
    return data;
}

void listar(struct stat pt, int longL, int link, int acc, char *path, char *fpath) {
    char data[MAX];

    if (longL) {
        printf("%s\n", get_info(pt, data, link, acc, path, fpath)); 
    } else {
        sprintf(data, "%9d ", (signed int) pt.st_size);
        strcat(data, path);
        printf("%s\n", data);
    }  
}

void listar_dir(int longL, int link, int acc, int hid, int recb, int reca, char *path);

void build_path(char *dest, char *path, char *add) {
    strcpy(dest, path);
    if (dest[strlen(dest) - 1] != '/') strcat(dest, "/");
    strcat(dest, add);
}

void do_recursive(DIR *dir, int longL, int link, int acc, int hid, int recb, int reca, char *path) {
    struct dirent *content;
    char it[MAX];
    struct stat pt;

    while ((content = readdir(dir)) != NULL) {
        if((strcmp(content->d_name, ".") == 0) || (strcmp(content->d_name, "..") == 0)) continue;
        build_path(it, path, content->d_name);
        if (lstat(it, &pt) == -1) {
            printf("Cannot access '%s': %s\n", it, strerror(errno));
            continue;
        }
        else {
            if ((content->d_name[0] != '.' || hid) && (S_ISDIR(pt.st_mode))) {
                listar_dir(longL, link, acc, hid, recb, reca, it);
            }   
        }
    }        
}

void listar_dir(int longL, int link, int acc, int hid, int recb, int reca, char *path) {
    struct stat pt;
    char it[MAX];
    DIR *dir;
    struct dirent *content;

    if (lstat(path, &pt) == -1) {
        printf("Cannot access '%s': %s\n", path, strerror(errno));
        return;
    } else {
        if (S_ISDIR(pt.st_mode)) {
            if ((dir = opendir(path)) == NULL) {
                printf("Cannot open dir '%s': %s\n", path, strerror(errno));
                return;
            } else {
                if (recb) {
                    do_recursive(dir, longL, link, acc, hid, recb, reca, path);
                    rewinddir(dir);
                }
                printf("----- DIR ----- %s\n", path);
                while ((content = readdir(dir)) != NULL) {
                    if (content->d_name[0] != '.' || hid) {
                        build_path(it, path, content->d_name);
                        if (lstat(it, &pt) == -1) {
                            printf("Cannot access '%s': %s\n", it, strerror(errno));
                            continue;
                        } else listar(pt, longL, link, acc, content->d_name, it);
                    }   
                }
                if (reca) {
                    rewinddir(dir);
                    do_recursive(dir, longL, link, acc, hid, recb, reca, path);
                }
                closedir(dir);
            }
        } else {
            listar(pt, longL, link, acc, path, path);
        }
    } 
}

void cmd_listfich(int chop_number, char *chops[]) {
    int longL = 0, link = 0, acc = 0, flags = 0;
    char path[MAX];
    struct stat pt;

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
            if (strncmp(chops[i], "/", 1) != 0 && strncmp(chops[i], "./", 2) != 0 && strncmp(chops[i], "../", 3) != 0 && strcmp(chops[i], ".") != 0 && strcmp(chops[i], "..") != 0) {
                strcpy(path, "./");
                strcat(path, chops[i]);
            } else {
                strcpy(path, chops[i]);
            }
            if (lstat(path, &pt) == -1) {
                printf("Cannot access '%s': %s\n", path, strerror(errno));
                continue;
            } else listar(pt, longL, link, acc, path, path);
        }
    }
}

void cmd_listdir(int chop_number, char *chops[]) {
    int longL = 0, link = 0, acc = 0, flags = 0, hid = 0, reca = 0, recb = 0;
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
            } else if (strcmp(chops[i], "-hid") == 0) {
                hid = 1;
                flags++;
            } else if (strcmp(chops[i], "-reca") == 0) {
                if (recb == 1) recb = 0;
                reca = 1;
                flags++;
            } else if (strcmp(chops[i], "-recb") == 0) {
                if (reca == 1) reca = 0;
                recb = 1;
                flags++;
            } else break;
        }

        if (flags == chop_number) {
            curr_dir();
            return;
        }

        for (int i = flags; i < chop_number; i++) {
            strcpy(path, chops[i]);
            if (strncmp(chops[i], "/", 1) != 0 && strncmp(chops[i], "./", 2) != 0 && strncmp(chops[i], "../", 3) != 0 && strcmp(chops[i], ".") != 0 && strcmp(chops[i], "..") != 0) {
                strcpy(path, "./");
                strcat(path, chops[i]);
            } else {
                strcpy(path, chops[i]);
            }
            listar_dir(longL, link, acc, hid, recb, reca, path);
        }
    }
}

/* Lab Assignment 2 */ 

void cmd_malloc(int chop_number, char *chops[]) {
    int tam;
    void *address;
    Node node;
    Node* del;
    if (chops[0] == NULL || ((chop_number == 1) & (strcmp(chops[0], "-free") == 0))) {
        printf("----------- Malloc allocated block list for process: %d -----------\n", getpid());
        showNodes(memlist, "malloc");
    } else {
        if (strcmp(chops[0], "-free") == 0) {
            if ((tam = atoi(chops[1])) == 0) {
                printf("Cannot deallocate blocks of %d bytes\n", tam);
                return;
            } else {
                if ((del = findNodeBySize((size_t) tam, "malloc", memlist)) == NULL) {
                    printf("There is no block of size %d allocated with malloc\n", tam);
                    return;
                } else {
                    free(del->address);
                    if (!removeNode(*del, &memlist)) {
                        printf("Could not delete from block list\n");
                    }
                }
            }
        } else {
            if ((tam = atoi(chops[0])) == 0) {
                printf("Cannot allocate blocks of %d bytes\n", tam);
                return;
            } else {
                if ((address = malloc((size_t) tam)) == NULL) {
                    perror("Cannot allocate");
                    return;
                } else {
                    node.address = address;
                    strcpy(node.alloc_type, "malloc");
                    node.size = (size_t) tam;
                    node.time = time(NULL);
                    if (insertNode(node, &memlist)) {
                        printf("Allocated %lu bytes in %p\n", node.size, node.address);
                    } else {
                        printf("Could not insert into block list\n");
                    }
                }
            }
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
    {"listdir", cmd_listdir},
    {"malloc", cmd_malloc},
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
    int chop_number;

    createEmptyHistory(&hist);
    createEmptyMemlist(&memlist);
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