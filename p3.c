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
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include "list.h"
#include "memlist.h"
#include "proclist.h"

#define MAX 1024
#define RSIZE 4096
#define LEERCOMPLETO ((ssize_t) - 1)

tHist hist;
tMemList memlist;
tProcList proclist;
int rec_counter = 0;
int global1 = 1, global2 = 2, global3 = 3;
int saved_stderr;
char** main3;
extern char ** environ;

struct CMD {
    char *name;
    void (*pf)(int, char **);
};

struct ayuda {
    char *command;
    char *description;
};

struct ayuda a[] = {
        {"autores",   "autores [-n|-l]	Show the names and logins of the authors"},
        {"pid",       "pid [-p]	Show the pid of this shell or from its parent process"},
        {"carpeta",   "carpeta [dir]	Change (or show) the current directory of the shell"},
        {"fecha",     "fecha [-d|-h]	Show the date and/or the current time"},
        {"hist",      "hist [-c|-N]	Show the historic of commands, use -c to delete it"},
        {"comando",   "comando [-N]	Repeat command N (from the historic)"},
        {"infosis",   "infosis 	Show information about the machine where the shell is running"},
        {"ayuda",     "ayuda [cmd]	Shows help about commands"},
        {"fin",       "fin 	Terminates the shell execution"},
        {"salir",     "salir 	Terminates the shell execution"},
        {"bye",       "bye 	Terminates the shell execution"},
        {"crear",     "crear [-f] [name]    Creates a file or a directory"},
        {"borrar",    "borrar [name1 name2 ..]    Delete files or empty directories"},
        {"borrarrec", "borrarrec [name1 name2 ..]   Delete files or non empty directories"},
        {"listfich",  "listfich [-long][-link][-acc] n1 n2 ..	List files"},
        {"listdir",   "listdir [-reca] [-recb] [-hid][-long][-link][-acc] n1 n2 ..	List files inside directories"},
        {"malloc",    "malloc [-free] tam      Allocates (or deallocates) memory in the program"},
        {"mmap",      "mmap [-free] fich [perm]        Map (or unmaps) files in the process address space"},
        {"shared",    "shared [-free | -create | -delkey] cl [tam]     Allocates (or deallocates) shared memory in the program"},
        {"dealloc",   "dealloc [-malloc | -shared| -mmap]....       Deallocates a memory block allocated with malloc, shared or mmap"},
        {"memoria",   "memoria [-blocks| -funcs| -vars| -all| -pmap]...       Shows details of the memory of the process"},
        {"volcarmem", "volcarmem addr [cont]      Dump on the screen the contents (cont bytes) of memory address addr"},
        {"llenarmem", "llenarmem addr [cont] [byte]     Fills memory with byte from addr"},
        {"recursiva", "recursiva [n]   Calls recursive function n times"},
        {"e-s",       "e-s [read|write] [-o] fich addr cont\n"
                      "With read, reads cont bytes from file fich into address addr\n"
                      "With write, writes cont bytes from memory address addr into file fich"},
        {"priority", "priority [pid] [valor]    Shows or changes the priority of process pid to valor"},
        {"rederr", "rederr [-reset] [fich]    Redirects the standard error of the shell"},
        {"entorno", "entorno [-environ | -addr]     Muestra el entorno del proceso"},
        {"mostrarvar", "Shows value and addresses of an environment variable"},
        {"cambiarvar", "cambiarvar [-a| -e| -p] var valor	Changes the value of an environment variable"},
        {"uid", "uid [-get| -set] [-l] [id]     Shows or changes (if possible) the credential of the process executing the shell"},
        {"fork", "fork      Makes a call to fork to create  a process"},
        {"ejec", "ejec prog args....       Executes, without creating a process, prog with arguments"},
        {"ejecpri", "ejecpri prio prog args....       Executes, without creating a process, prog with arguments and priority set to prio"},
        {"fg", "fg prog args...     Creates a process executed in foreground with arguments"},
        {"fgpri", "fgpri prio prog args...      Creates a process executed in foreground with arguments and priority set to prio"},
        {"back", "back prog args...     Creates a process executed in background with arguments"},
        {"backpri", "backpri prio prog args...      Creates a process executed in background with arguments and priority set to prio"},
        {"ejecas", "ejecas user prog args..     Executes, without creating a process and with user as user, prog with arguments"},
        {"fgas", "fgas login prog args...      Creates a process prog executed in foreground, as user login, with arguments args"},
        {"bgas", "bgas login prog args...      Creates a process prog executed in background, as user login, with arguments args"},
        {"listjobs", "listjobs      Lists processes executing in background"},
        {"job", "job [-fg] pid      Shows information about process pid. -fg brings it to foreground"},
        {"borrarjobs", "borrarjobs [-term][-sig]       Remove the process terminated normally or terminated by signal from the list of background processes"},
        {NULL,        NULL}
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

    strftime(buffer, sizeof(buffer), "%d/%m/%Y", info);
    printf("%s\n", buffer);
}

void solo_hora() {
    char *tr[8];

    time_t t;
    time(&t);
    chop_input(ctime(&t), tr);
    printf("%s\n", tr[3]);
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
    char *remaining, *command, *cmd_chops[MAX / 2], command_cpy[MAX];

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
        printf("%s (%s), OS: %s%s%s\n", uname_content.nodename, uname_content.machine, uname_content.sysname,
               uname_content.release, uname_content.version);
    }
}

void cmd_ayuda(int chop_number, char *chops[]) {
    if (chops[0] == NULL) {
        printf("'ayuda cmd' where cmd is one of the following commands:\n"
               "fin salir bye fecha pid autores hist comando carpeta infosis ayuda crear borrar borrarrec listfich listdir "
               "recursiva e-s volcarmem llenarmem dealloc malloc mmap shared memoria "
               "priority rederr entorno mostrarvar cambiarvar uid fork ejec ejecpri fg fgpri back backpri ejecas fgas bgas listjobs job borrarjobs\n");
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

void exit_error(int n) {
    clearProcList(&proclist);
    deleteHistory(&hist);
    deleteMemlist(&memlist);
    exit(n);
}

void cmd_bye() {
    clearProcList(&proclist);
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

char *ConvierteModo(mode_t m, char *permisos) {
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

void delete(char *tr, int rec) {
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
                    while ((entry = readdir(dir)) != NULL) {
                        if (entry->d_name[0] == '.') continue;
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

void cmd_borrar(int chop_number, char *chops[]) {
    int i = 0;

    if (chops[0] == NULL) {
        curr_dir();
        return;
    } else {
        while (chops[i] != NULL) {
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
    strcat(data, builder);
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
    if (S_ISLNK(pt.st_mode) && link) {
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
        if ((strcmp(content->d_name, ".") == 0) || (strcmp(content->d_name, "..") == 0)) continue;
        build_path(it, path, content->d_name);
        if (lstat(it, &pt) == -1) {
            printf("Cannot access '%s': %s\n", it, strerror(errno));
            continue;
        } else {
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
            if (strcmp(chops[i], "-long") == 0) {
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
            if (strncmp(chops[i], "/", 1) != 0 && strncmp(chops[i], "./", 2) != 0 && strncmp(chops[i], "../", 3) != 0 &&
                strcmp(chops[i], ".") != 0 && strcmp(chops[i], "..") != 0) {
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
            if (strcmp(chops[i], "-long") == 0) {
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
            if (strncmp(chops[i], "/", 1) != 0 && strncmp(chops[i], "./", 2) != 0 && strncmp(chops[i], "../", 3) != 0 &&
                strcmp(chops[i], ".") != 0 && strcmp(chops[i], "..") != 0) {
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

void malloc_free(size_t tam) {
    Node *del;
    if ((del = findNodeBySize(tam, "malloc", memlist)) == NULL) {
        printf("There is no block of size %lu allocated with malloc\n", tam);
        printf("----------- Malloc allocated block list for process: %d -----------\n", getpid());
        showNodes(memlist, "malloc");
    } else {
        free(del->address);
        if (!removeNode(*del, &memlist)) {
            printf("Could not delete from block list\n");
        }
    }
}

void cmd_malloc(int chop_number, char *chops[]) {
    size_t tam;
    void *address;
    Node node;
    if (chops[0] == NULL || ((chop_number == 1) & (strcmp(chops[0], "-free") == 0))) {
        printf("----------- Malloc allocated block list for process: %d -----------\n", getpid());
        showNodes(memlist, "malloc");
    } else {
        if (strcmp(chops[0], "-free") == 0) {
            if ((tam = (size_t) atoll(chops[1])) == 0) {
                printf("Cannot deallocate blocks of %ld bytes\n", tam);
            } else {
                malloc_free(tam);
            }
        } else {
            if ((tam = (size_t) atoll(chops[0])) == 0) {
                printf("Cannot allocate blocks of %ld bytes\n", tam);
            } else {
                if ((address = malloc(tam)) == NULL) {
                    perror("Cannot allocate");
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

void *MmapFichero(char *fichero, int protection) {
    int df, map = MAP_PRIVATE, modo = O_RDONLY;
    struct stat s;
    void *p;
    Node node;
    if (protection & PROT_WRITE) modo = O_RDWR;
    if (stat(fichero, &s) == -1 || (df = open(fichero, modo)) == -1)
        return NULL;
    if ((p = mmap(NULL, s.st_size, protection, map, df, 0)) == MAP_FAILED)
        return NULL;
    node.address = p;
    node.size = s.st_size;
    node.time = time(NULL);
    strcpy(node.alloc_type, "mapped file");
    strcpy(node.name, fichero);
    node.key = df;
    if (insertNode(node, &memlist) == 0) printf("Could not insert into block list\n");
    return p;
}

void mmap_free(char *name) {
    Node *del;
    if ((del = findNodeByName(name, "mapped file", memlist)) == NULL) {
        printf("File %s not mapped\n", name);
        printf("----------- List of mmap allocated blocks for process: %d -----------\n", getpid());
        showNodes(memlist, "mapped file");
    } else {
        if (munmap(del->address, del->size) == -1) {
            perror("Could not unmap file");
        } else {
            if (close(del->key) == -1) {
                perror("Could not close file");
            } else {
                if (!removeNode(*del, &memlist)) {
                    printf("Could not delete from block list\n");
                }
            }
        }
    }
}

void cmd_mmap(int chop_number, char *chops[]) {
    int protection = 0;
    char *perm;
    void *p;
    if (chops[0] == NULL || ((chop_number == 1) & (strcmp(chops[0], "-free") == 0))) {
        printf("----------- List of mmap allocated blocks for process: %d -----------\n", getpid());
        showNodes(memlist, "mapped file");
    } else {
        if (strcmp(chops[0], "-free") == 0) {
            mmap_free(chops[1]);
        } else {
            if ((perm = chops[1]) != NULL && strlen(perm) < 4) {
                if (strchr(perm, 'r') != NULL) protection |= PROT_READ;
                if (strchr(perm, 'w') != NULL) protection |= PROT_WRITE;
                if (strchr(perm, 'x') != NULL) protection |= PROT_EXEC;
            }
            if ((p = MmapFichero(chops[0], protection)) == NULL)
                perror("Could not map file");
            else
                printf("File %s mapped at %p\n", chops[0], p);
        }
    }
}

void *ObtenerMemoriaShmget(key_t clave, size_t tam) {
    void *p;
    int aux, id, flags = 0777;
    struct shmid_ds s;
    Node node;
    if (tam)
        flags = flags | IPC_CREAT | IPC_EXCL;
    if (clave == IPC_PRIVATE) {
        errno = EINVAL;
        return NULL;
    }
    if ((id = shmget(clave, tam, flags)) == -1)
        return (NULL);
    if ((p = shmat(id, NULL, 0)) == (void *) -1) {
        aux = errno;
        if (tam)
            shmctl(id, IPC_RMID, NULL);
        errno = aux;
        return (NULL);
    }
    shmctl(id, IPC_STAT, &s);
    node.address = p;
    node.size = s.shm_segsz;
    node.time = time(NULL);
    strcpy(node.alloc_type, "shared memory");
    node.key = clave;
    if (insertNode(node, &memlist) == 0) printf("Could not insert into block list\n");
    return (p);
}

void free_shared(key_t key) {
    Node *del;
    if ((del = findNodeByKey(key, "shared memory", memlist)) == NULL) {
        printf("There is no block with that key in the process\n");
        printf("----------- List of shared allocated blocks for process: %d -----------\n", getpid());
        showNodes(memlist, "shared memory");
    } else {
        if (shmdt(del->address) == -1) {
            perror("Cannot free memory");
        } else {
            if (!removeNode(*del, &memlist)) {
                printf("Could not delete from block list\n");
            }
        }
    }
}

void delete_key(key_t key) {
    int id;
    if (key == IPC_PRIVATE) {
        errno = EINVAL;
        perror("Cannot delete key");
    } else {
        if ((id = shmget(key, 0, 0666)) == -1) {
            perror("Cannot delete key: shmget");
        } else {
            if (shmctl(id, IPC_RMID, NULL) == -1) {
                perror("Cannot delete key: shmctl");
            }
        }
    }
}

void cmd_shared(int chop_number, char *chops[]) {
    key_t k;
    size_t tam = 0;
    void *p;
    char *aux_tam, *aux_key;
    if (chops[0] == NULL || (chop_number == 1) & (strcmp(chops[0], "-free") == 0) ||
        (chop_number <= 2) & (strcmp(chops[0], "-create") == 0)) {
        printf("----------- List of shared allocated blocks for process: %d -----------\n", getpid());
        showNodes(memlist, "shared memory");
    } else {
        if (strcmp(chops[0], "-delkey") == 0) {
            if (chops[1] == NULL) {
                printf("shared -delkey needs a valid key\n");
            } else {
                delete_key((key_t) strtoul(chops[1], NULL, 10));
            }
        } else if (strcmp(chops[0], "-free") == 0) {
            free_shared((key_t) atoi(chops[1]));
        } else {
            if (strcmp(chops[0], "-create") == 0) {
                aux_tam = strdup(chops[2]);
                aux_key = strdup(chops[1]);
            } else {
                aux_key = strdup(chops[0]);
                aux_tam = NULL;
            }
            k = (key_t) atoi(aux_key);
            if (aux_tam != NULL) {
                tam = (size_t) atoll(aux_tam);
            }
            free(aux_tam);
            free(aux_key);
            if ((p = ObtenerMemoriaShmget(k, tam)) == NULL)
                perror("Cannot get shmget memory");
            else
                printf("Shmget memory with key %d allocated at %p\n", k, p);
        }
    }
}

void cmd_dealloc(int chop_number, char *chops[]) {
    Node *del;
    size_t tam;
    if (chops[0] == NULL) {
        printf("----------- List of allocated blocks for process: %d -----------\n", getpid());
        showNodes(memlist, "-all");
    } else {
        if (strcmp(chops[0], "-malloc") == 0) {
            if (chops[1] == NULL) {
                printf("----------- List of malloc allocated blocks for process: %d -----------\n", getpid());
                showNodes(memlist, "malloc");
            } else {
                if ((tam = (size_t) atoll(chops[1])) == 0) {
                    printf("Cannot deallocate blocks of %ld bytes\n", tam);
                } else {
                    malloc_free(tam);
                }
            }
        } else if (strcmp(chops[0], "-shared") == 0) {
            if (chops[1] == NULL) {
                printf("----------- List of shared allocated blocks for process: %d -----------\n", getpid());
                showNodes(memlist, "shared memory");
            } else {
                free_shared((key_t) atoi(chops[1]));
            }
        } else if (strcmp(chops[0], "-mmap") == 0) {
            if (chops[1] == NULL) {
                printf("----------- List of mmap allocated blocks for process: %d -----------\n", getpid());
                showNodes(memlist, "mapped file");
            } else {
                mmap_free(chops[1]);
            }
        } else {
            if ((del = findNodeByAddress(chops[0], memlist)) == NULL) {
                printf("Cannot find block with this address in the list:\n");
                showNodes(memlist, "-all");
            } else {
                if (strcmp(del->alloc_type, "malloc") == 0) malloc_free(del->size);
                else if (strcmp(del->alloc_type, "mapped file") == 0) mmap_free(del->name);
                else if (strcmp(del->alloc_type, "shared memory") == 0) free_shared(del->key);
            }
        }
    }
}

void memoria_vars() {
    int local1 = 1, local2 = 2, local3 = 3;
    static int static1 = 1, static2 = 2, static3 = 3;
    printf("----------- Global Variables -----------\n");
    printf("Global variable 1: %p\n", &global1);
    printf("Global variable 2: %p\n", &global2);
    printf("Global variable 3: %p\n", &global3);
    printf("\n");
    printf("----------- Static Variables -----------\n");
    printf("Static variable 1: %p\n", &static1);
    printf("Static variable 2: %p\n", &static2);
    printf("Static variable 3: %p\n", &static3);
    printf("\n");
    printf("----------- Local Variables -----------\n");
    printf("Local variable 1: %p\n", &local1);
    printf("Local variable 2: %p\n", &local2);
    printf("Local variable 3: %p\n", &local3);
}

void memoria_funcs() {
    printf("----------- Program Functions -----------\n");
    printf("cmd_malloc function: %p\n", cmd_malloc);
    printf("cmd_shared function: %p\n", cmd_shared);
    printf("cmd_mmap function: %p\n", cmd_mmap);
    printf("\n");
    printf("----------- Library Functions -----------\n");
    printf("strdup function: %p\n", strdup);
    printf("strcat function: %p\n", strcat);
    printf("strcmp function: %p\n", strcmp);
}

void dopmap() {
    pid_t pid;
    char elpid[32];
    char *argv[3] = {
            "pmap",
            elpid,
            NULL
    };
    sprintf(elpid, "%d", (int) getpid());
    if ((pid = fork()) == -1) {
        perror("Cannot create process");
        return;
    }
    if (pid == 0) {
        if (execvp(argv[0], argv) == -1)
            perror("Cannot execute pmap");
        exit(1);
    }
    waitpid(pid, NULL, 0);
}

void cmd_memoria(int chop_number, char *chops[]) {
    if (chops[0] == NULL || strcmp(chops[0], "-all") == 0) {
        printf("----------- List of allocated blocks for process: %d -----------\n", getpid());
        showNodes(memlist, "-all");
        printf("\n");
        memoria_vars();
        printf("\n");
        memoria_funcs();
    } else {
        if (strcmp(chops[0], "-blocks") == 0) {
            printf("----------- List of allocated blocks for process: %d -----------\n", getpid());
            showNodes(memlist, "-all");
        } else if (strcmp(chops[0], "-vars") == 0) {
            memoria_vars();
        } else if (strcmp(chops[0], "-funcs") == 0) {
            memoria_funcs();
        } else if (strcmp(chops[0], "-pmap") == 0) {
            dopmap();
        }
    }
}

void cmd_volcarmem(int chop_number, char *chops[]) {
    int cont = 25, remain = 25, loop_cycles = 25;
    char *address;
    char character;
    if (chops[0] == NULL) {
        printf("Missing memory address to dump\n");
    } else {
        address = (char *) strtoul(chops[0], NULL, 16);
        if (chops[1] != NULL) {
            cont = atoi(chops[1]);
            remain = cont;
            if (cont < 25) loop_cycles = cont;
        }
        printf("Dump %d bytes from address %p\n", cont, address);
        for (int i = 0; i < cont; i += 25) {
            if (remain == 0) break;
            for (int j = 0; j < loop_cycles; j++) {
                character = *(i + j + address);
                if ((character >= 32) & (character < 127))
                    printf(" %2c ", character);
                else
                    printf("    ");
            }
            printf("\n");
            for (int j = 0; j < loop_cycles; j++) {
                character = *(i + j + address);
                printf(" %02X ", (unsigned char) character);
                remain--;
            }
            if (remain < 25) loop_cycles = remain;
            printf("\n");
        }
    }
}

void cmd_llenarmem(int chop_number, char *chops[]) {
    char *address;
    int cont = 128;
    char default_byte = 'A';
    if (chops[0] == NULL) {
        printf("Missing memory address to fill\n");
    } else {
        address = (char *) strtoul(chops[0], NULL, 16);
        if (chops[1] != NULL) {
            if ((chop_number == 2) & (strncmp(chops[1], "0x", 2) == 0 || strncmp(chops[1], "0X", 2) == 0))
                default_byte = strtoul(chops[1], NULL, 16);
            else cont = atoi(chops[1]);
        }
        if (chop_number == 3)
            default_byte = strtoul(chops[2], NULL, 16);
        for (int i = 0; i < cont; i++) address[i] = default_byte;
        printf("Filling %d bytes from address %p with %c(%x)\n", cont, address, default_byte,
               (unsigned char) default_byte);
    }
}

void recursive(int n) {
    char automatic[RSIZE];
    static char estatic[RSIZE];
    printf("parameter n:%d in %p\n", n, &n);
    printf("static array in:%p \n", estatic);
    printf("automatic array in %p\n", automatic);
    n--;
    if (n >= 0) recursive(n);
}

void cmd_recursiva(int chop_number, char *chops[]) {
    int param;
    char *remain;
    if (chops[0] == NULL) printf("Missing parameter\n");
    else {
        param = strtoul(chops[0], &remain, 10);
        if (remain == chops[0]) {
            printf("Parameter must be a number\n");
            return;
        }
        if (param >= 0) recursive(param);
        else printf("Parameter must be a number greater than or equal to 0\n");
    }
}

ssize_t LeerFichero(char *fich, void *p, ssize_t n) {
    ssize_t nleidos, tam = n;
    int df, aux;
    struct stat s;
    if (stat(fich, &s) == -1 || (df = open(fich, O_RDONLY)) == -1)
        return ((ssize_t) - 1);
    if (n == LEERCOMPLETO)
        tam = (ssize_t) s.st_size;
    if ((nleidos = read(df, p, tam)) == -1) {
        aux = errno;
        close(df);
        errno = aux;
        return ((ssize_t) - 1);
    }
    close(df);
    return (nleidos);
}

void do_write(int chop_number, char *chops[]) {
    ssize_t cont;
    char *addr;
    int o = 0, fd, flags = O_CREAT | O_EXCL | O_WRONLY;
    if (chop_number < 3) {
        printf("Missing parameters\n");
    } else {
        if (strcmp(chops[0], "-o") == 0) {
            flags = O_CREAT | O_WRONLY | O_TRUNC;
            o = 1;
        }
        cont = (ssize_t) atoi(chops[2 + o]);
        addr = (char *) strtoul(chops[1 + o], NULL, 16);
        if ((fd = open(chops[0 + o], flags, 0744)) == -1) {
            perror("Cannot open or create file");
        } else {
            if (write(fd, addr, cont) == -1) {
                perror("Cannot write file");
            } else {
                printf("%d bytes written into file %s\n", (int) cont, chops[0 + o]);
            }
            close(fd);
        }
    }
}

void do_read(int chop_number, char *chops[]) {
    ssize_t size, cont = LEERCOMPLETO;
    char *addr;
    if (chop_number < 2) {
        printf("Missing parameters\n");
    } else {
        if (chops[2] != NULL) {
            cont = (ssize_t) atoi(chops[2]);
        }
        addr = (char *) strtoul(chops[1], NULL, 16);
        if ((size = LeerFichero(chops[0], addr, cont)) == -1) {
            perror("Cannot read file");
        } else {
            printf("%d bytes read from file %s\n", (int) size, chops[0]);
        }
    }
}

void cmd_es(int chop_number, char *chops[]) {
    if (chops[0] == NULL || ((strcmp(chops[0], "read") != 0) & (strcmp(chops[0], "write") != 0))) {
        printf("Usage: e-s [read | write] ......\n");
    } else {
        if (strcmp(chops[0], "read") == 0) {
            do_read(chop_number - 1, chops + 1);
        } else {
            do_write(chop_number - 1, chops + 1);
        }
    }
}

/* Lab Assignment 3 */

int CambiarPrioridad(pid_t pid, int priority) {
    if (setpriority(PRIO_PROCESS, pid, priority) == -1) {
        perror("Cannot set priority");
        return 0;
    } else return 1;
}

void cmd_priority(int chop_number, char *chops[]) {
    int priority;
    int pid;
    if (chop_number < 1) {
        if ((priority = getpriority(PRIO_PROCESS, getpid())) == -1 ) {
            perror("Cannot get priority");
        } else
            printf("The priority of process %d is %d\n", getpid(), priority);
    } else {
        if (chop_number == 1) {
            pid = atoi(chops[0]);
            if ((priority = getpriority(PRIO_PROCESS, pid)) == -1 ) {
                perror("Cannot get priority");
            } else
                printf("The priority of process %d is %d\n", pid, priority);
        } else if (chop_number >= 2) {
            pid = atoi(chops[0]);
            priority = atoi(chops[1]);
            CambiarPrioridad(pid, priority);
        }
    }
}

void cmd_rederr(int chop_number, char* chops[]) {
    char path[255], filename[255] = "";
    int fd;
    if (chops[0] == NULL) {
        sprintf(path, "/proc/%d/fd/2", getpid());
        if (readlink(path, filename, sizeof(filename) - 1) == -1) {
            perror("Could not get location of standard error file");
        } else {
            filename[sizeof(filename) - 1] = '\0';
            if (strcmp(filename, "/dev/pts/0") == 0) printf("Standard error is in the original configuration file\n");
            else printf("Standard error is in file: %s\n", filename);
        }
    } else if (strcmp(chops[0], "-reset") == 0) {
        if (dup2(saved_stderr, STDERR_FILENO) == -1) {
            perror("Could not reset standard error");
        }
        close(saved_stderr);
    } else {
        if ((fd = open(chops[0], O_CREAT | O_EXCL | O_WRONLY, 0744)) == -1) {
            perror("Could not open file to redirect");
        } else {
            saved_stderr = dup(STDERR_FILENO);
            if (dup2(fd, STDERR_FILENO) == -1) {
                perror("Could not redirect standard error");
            }
            close(fd);
        }
    }
}

void MostrarEntorno(char ** entorno, char * nombre_entorno) {
    int i = 0;
    while (entorno[i] != NULL) {
        printf("%p->%s[%d]=(%p) %s\n", &entorno[i],
               nombre_entorno, i, entorno[i], entorno[i]);
        i++;
    }
}

void cmd_entorno(int chop_number, char* chops[]) {
    if (chops[0] == NULL)
        MostrarEntorno(main3, "main arg3");
    else if (strcmp(chops[0], "-environ") == 0)
        MostrarEntorno(environ, "environ");
    else if (strcmp(chops[0], "-addr") == 0) {
        printf("environ: %p (stored at %p)\n", environ, &environ);
        printf("main arg3: %p (stored at %p)\n", main3, &main3);
    }
}

int BuscarVariable(char *var, char *e[]) {
    int pos = 0;
    char aux[MAX] = "";
    strcpy(aux, var);
    strcat(aux, "=");
    while (e[pos] != NULL)
        if (!strncmp(e[pos], aux, strlen(aux)))
            return (pos);
        else
            pos++;
    errno = ENOENT;
    return (-1);
}

void mostrarvar_aux(char* var, char *nombre_ent, char *ent[]) {
    int pos;
    printf("With %s: ", nombre_ent);
    if ((pos = BuscarVariable(var, ent)) == -1) {
        printf("Could not find var: %s\n", strerror(errno));
    } else printf("%s (%p) @%p\n", ent[pos], ent[pos], &ent[pos]);
}

void cmd_mostrarvar(int chop_number, char *chops[]) {
    char *envV;
    if (chops[0] == NULL) MostrarEntorno(main3, "main arg3");
    else {
        mostrarvar_aux(chops[0], "main arg3", main3);
        mostrarvar_aux(chops[0], "environ", environ);
        if ((envV = getenv(chops[0])) == NULL) {
            printf("With getenv: Could not find environment variable\n");
        } else {
            printf("With getenv: %s (%p)\n", envV, envV);
        }
    }
}

int CambiarVariable(char * var, char * valor, char * e[]) {
    int pos;
    char * aux;
    if ((pos = BuscarVariable(var, e)) == -1)
        return (-1);
    if ((aux = (char * ) malloc(strlen(var) + strlen(valor) + 2)) == NULL)
        return -1;
    strcpy(aux,var);
    strcat(aux, "=");
    strcat(aux, valor);
    e[pos] = aux;
    return (pos);
}

void cmd_cambiarvar(int chop_number, char *chops[]) {
    char var_constructor[MAX]= "";
    if (chop_number == 3) {
        if (strcmp(chops[0], "-a") == 0) {
            if (CambiarVariable(chops[1], chops[2], main3) == -1) perror("Impossible to change var");
            return;
        } else if (strcmp(chops[0], "-e") == 0) {
            if (CambiarVariable(chops[1], chops[2], environ) == -1) perror("Impossible to change var");
            return;
        } else if (strcmp(chops[0], "-p") == 0) {
            sprintf(var_constructor, "%s=%s", chops[1], chops[2]);
            if (putenv(strdup(var_constructor)) != 0) {
                perror("Cannot change / add var");
            }
            return;
        }
    }
    printf("Usage: cambiarvar [-a | -e | -p] var valor\n");
}

char * NombreUsuario(uid_t uid) {
    struct passwd * p;
    if ((p = getpwuid(uid)) == NULL)
        return ("??????");
    return p -> pw_name;
}

void MostrarUidsProceso() {
    uid_t real = getuid(), efec = geteuid();
    printf("Real credential: %d, (%s)\n", real, NombreUsuario(real));
    printf("Effective credential: %d, (%s)\n", efec, NombreUsuario(efec));
}

uid_t UidUsuario(char * nombre) {
    struct passwd * p;
    if ((p = getpwnam(nombre)) == NULL)
        return (uid_t) - 1;
    return p -> pw_uid;
}

int CambiarUid(char * login, int l) {
    uid_t uid;
    if (!l) {
        if ((uid = (uid_t) atoi(login)) < 0) uid = (uid_t) -1;
        if (uid == (uid_t) -1) {
            printf("Invalid credential: %s\n", login);
            return 0;
        }
    } else {
        if ((uid = UidUsuario(login)) == (uid_t) - 1) {
            printf("Invalid login: %s\n", login);
            return 0;
        }
    }
    if (setuid(uid) == -1) {
        printf("Impossible to change credential: %s\n", strerror(errno));
        return 0;
    } else return 1;
}

void cmd_uid(int chop_number, char *chops[]) {
    int arg_l = 0;
    if (chop_number <= 1) {
        MostrarUidsProceso();
    } else {
        if (strcmp(chops[1], "-l") == 0) arg_l = 1;
        CambiarUid(chops[1 + arg_l], arg_l);
    }
}

void cmd_fork(int chop_number, char *chops[]) {
    pid_t pid;
    if ((pid = fork()) == 0) {
        clearProcList(&proclist);
        printf("Child created. Child's pid -> %d\n", getpid());
    } else if (pid == -1) perror("No child process was created");
    else {
        if (waitpid(pid, NULL, 0) == -1) {
            perror("There was a problem suspending the execution of the parent");
        }
    }
}

int execute_command(char *command, char *args[]) {
    if (execvp(command, args) == -1) {
        perror("Could not execute command");
        return 0;
    } else return 1;
}

void cmd_ejec(int chop_number, char *chops[]) {
    if (chops[0] == NULL) printf("Missing parameters\n");
    else {
        execute_command(chops[0], chops);
    }
}

void cmd_ejecpri(int chop_number, char *chops[]) {
    pid_t pid = getpid();
    int priority;
    if (chop_number < 2) printf("Missing parameters\n");
    else {
        priority = atoi(chops[0]);
        if (CambiarPrioridad(pid, priority) == 0) return;
        execute_command(chops[1], &chops[1]);
    }
}

void execute_foreground(char *command, char *args[], int isPri, int isLogin) {
    pid_t pid;
    if ((pid = fork()) == 0) {
        if (isLogin) {
            if (CambiarUid(args[0], 1) == 0) exit_error(255);
        }
        if (isPri) {
            if (CambiarPrioridad(pid, atoi(args[0])) == 0) exit_error(255);
        }
        if (execute_command(command, &args[0 + isPri + isLogin]) == 0) exit_error(EXIT_FAILURE);
    }
    else if (pid == -1) perror("No process was created");
    else {
        if (waitpid(pid, NULL, 0) == -1) perror("There was a problem suspending the parent execution");
    }
}

void cmd_fg(int chop_number, char *chops[]) {
    if (chops[0] == NULL) printf("Missing parameters\n");
    else execute_foreground(chops[0], chops, 0, 0);
}

void cmd_fgpri(int chop_number, char *chops[]) {
    if (chop_number < 2) printf("Missing parameters\n");
    else execute_foreground(chops[1], chops, 1, 0);
}

void execute_background(char * command, char *args[], int args_len, int isPri, int isLogin) {
    pid_t pid;
    int counter = 0 + isPri + isLogin;
    if ((pid = fork()) == 0) {
        if (isLogin) {
            if (CambiarUid(args[0], 1) == 0) exit_error(255);
        }
        if (isPri) {
            if (CambiarPrioridad(pid, atoi(args[0])) == 0) exit_error(255);
        }
        if (execute_command(command, &args[0 + isPri + isLogin]) == 0) exit_error(EXIT_FAILURE);
    } else if (pid == -1) perror("No process was created");
    else {
        data proc;
        proc.pid = pid;
        proc.priority = getpriority(PRIO_PROCESS, pid);
        strcpy(proc.user, NombreUsuario(isLogin ? UidUsuario(args[0]) : geteuid()));
        strcpy(proc.command, "");
        while(counter < args_len) {
            strcat(proc.command, args[counter]);
            strcat(proc.command, " ");
            counter++;
        }
        proc.time = time(NULL);
        strcpy(proc.state, "Running");
        if (insertProc(proc, &proclist) == 0) printf("Could not insert process in the list\n");
    }
}

void cmd_back(int chop_number, char *chops[]) {
    if (chops[0] == NULL) printf("Missing parameters\n");
    else execute_background(chops[0], chops, chop_number, 0, 0);
}

void cmd_backpri(int chop_number, char *chops[]) {
    if (chop_number < 2) printf("Missing parameters\n");
    else execute_background(chops[1], chops, chop_number, 1, 0);
}

void cmd_ejecas(int chop_number, char *chops[]) {
    if (chop_number < 2) printf("Missing parameters\n");
    else {
        if (CambiarUid(chops[0], 1) == 0) return;
        else execute_command(chops[1], &chops[1]);
    }
}

void cmd_fgas(int chop_number, char *chops[]) {
    if (chop_number < 2) printf("Missing parameters\n");
    else execute_foreground(chops[1], chops, 0, 1);
}

void cmd_bgas(int chop_number, char *chops[]) {
    if (chop_number < 2) printf("Missing parameters\n");
    else execute_background(chops[1], chops, chop_number, 0, 1);
}

void cmd_listjobs() {
    updateProcList(&proclist);
    showProcList(proclist);
}

void cmd_job(int chop_number, char * chops[]) {
    pid_t pid;
    tPos pos;
    data* proc;
    int fg = 0, state;
    if (chops[0] == NULL) cmd_listjobs();
    else {
        if (strcmp(chops[0], "-fg") == 0) {
            if (chop_number < 2) {
                cmd_listjobs();
                return;
            }
            fg = 1;
        }
        pid = (pid_t) atoi(chops[0 + fg]);
        updateProcList(&proclist);
        if ((pos = findProc(pid, proclist)) == -1) {
            showProcList(proclist);
            return;
        } else {
            proc = getProc(pos, proclist);
            if (fg) {
                if (strcmp(proc->state, "Terminated By Signal") == 0 || strcmp(proc->state, "Terminated Normally") == 0 ) {
                    printf("Process %d is already finished\n", pid);
                } else {
                    if (waitpid(pid, &state, 0) == -1) perror("There was a problem bringing to foreground");
                    else {
                        if (WIFEXITED(state)) {
                            printf("Process %d terminated normally with value %d\n", pid, WEXITSTATUS(state));
                            if (removeProcByPid(pid, &proclist) == 0) printf("Could not remove process %d from the list\n", pid);
                        } else if (WIFSIGNALED(state)) {
                            printf("Process %d terminated by signal %s\n", pid, NombreSenal(WTERMSIG(state)));
                            if (removeProcByPid(pid, &proclist) == 0) printf("Could not remove process %d from the list\n", pid);
                        }
                    }
                }
            } else printProc(*proc);
        }
    }
}

void cmd_borrarjobs(int chop_number, char *chops[]) {
    if (chops[0] == NULL) cmd_listjobs();
    else {
        if (strcmp(chops[0], "-clear") == 0) {
            updateProcList(&proclist);
            clearProcList(&proclist);
        } else if (strcmp(chops[0], "-term") == 0) {
            updateProcList(&proclist);
            if (removeProcs("Terminated Normally", &proclist) == 0) cmd_listjobs();
        } else if (strcmp(chops[0], "-sig") == 0) {
            updateProcList(&proclist);
            if (removeProcs("Terminated By Signal", &proclist) == 0) cmd_listjobs();
        } else if (strcmp(chops[0], "-all") == 0) {
            updateProcList(&proclist);
            if (removeProcs("-all", &proclist) == 0) cmd_listjobs();
        } else cmd_listjobs();
    }
}

void execute_prog(int chop_number, char *chops[]) {
    if (strcmp(chops[chop_number - 1], "&") == 0) {
        chops[chop_number - 1] = NULL;
        execute_background(chops[0], chops, chop_number - 1, 0, 0);
    } else {
        execute_foreground(chops[0], chops, 0, 0);
    }
}

struct CMD c[] = {
        {"autores",   cmd_autores},
        {"pid",       cmd_pid},
        {"carpeta",   cmd_carpeta},
        {"fecha",     cmd_fecha},
        {"hist",      cmd_hist},
        {"comando",   cmd_comando},
        {"infosis",   cmd_uname},
        {"ayuda",     cmd_ayuda},
        {"fin",       cmd_bye},
        {"salir",     cmd_bye},
        {"bye",       cmd_bye},
        {"crear",     cmd_crear},
        {"borrar",    cmd_borrar},
        {"borrarrec", cmd_borrarrec},
        {"listfich",  cmd_listfich},
        {"listdir",   cmd_listdir},
        {"malloc",    cmd_malloc},
        {"mmap",      cmd_mmap},
        {"shared",    cmd_shared},
        {"dealloc",   cmd_dealloc},
        {"memoria",   cmd_memoria},
        {"volcarmem", cmd_volcarmem},
        {"llenarmem", cmd_llenarmem},
        {"recursiva", cmd_recursiva},
        {"e-s",       cmd_es},
        {"priority", cmd_priority},
        {"rederr", cmd_rederr},
        {"entorno", cmd_entorno},
        {"mostrarvar", cmd_mostrarvar},
        {"cambiarvar", cmd_cambiarvar},
        {"uid", cmd_uid},
        {"fork", cmd_fork},
        {"ejec", cmd_ejec},
        {"ejecpri", cmd_ejecpri},
        {"fg", cmd_fg},
        {"fgpri", cmd_fgpri},
        {"back", cmd_back},
        {"backpri", cmd_backpri},
        {"ejecas", cmd_ejecas},
        {"fgas", cmd_fgas},
        {"bgas", cmd_bgas},
        {"listjobs", cmd_listjobs},
        {"job", cmd_job},
        {"borrarjobs", cmd_borrarjobs},
        {NULL,        NULL}
};

int chop_input(char *cadena, char *trozos[]) {
    int i = 1;
    if ((trozos[0] = strtok(cadena, " \n\t")) == NULL) return 0;
    while ((trozos[i] = strtok(NULL, " \n\t")) != NULL) i++;
    return i;
}

void process_input(int chop_number, char *chops[]) {
    for (int i = 0; c[i].name != NULL; i++) {
        if (strcmp(chops[0], c[i].name) == 0) {
            (*c[i].pf)(chop_number - 1, chops + 1);
            return;
        }
    }
    execute_prog(chop_number, chops);
}

int main(int argc, char *argv[], char **envp) {
    char user_input[MAX];
    char *chops[MAX / 2];
    int chop_number;
    main3 = envp;

    createProcList(&proclist);
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
    
    return 0;
}