/*
    Daniel Ferreiro Villamor: d.ferreiro
    Martín Azpilcueta Rabuñal: m.azpilcueta
*/

#include "proclist.h"

/******************************SENALES ******************************************/
struct SEN {
    char *nombre;
    int senal;
};

static struct SEN sigstrnum[] = {
        {"HUP", SIGHUP},
        {"INT", SIGINT},
        {"QUIT", SIGQUIT},
        {"ILL", SIGILL},
        {"TRAP", SIGTRAP},
        {"ABRT", SIGABRT},
        {"IOT", SIGIOT},
        {"BUS", SIGBUS},
        {"FPE", SIGFPE},
        {"KILL", SIGKILL},
        {"USR1", SIGUSR1},
        {"SEGV", SIGSEGV},
        {"USR2", SIGUSR2},
        {"PIPE", SIGPIPE},
        {"ALRM", SIGALRM},
        {"TERM", SIGTERM},
        {"CHLD", SIGCHLD},
        {"CONT", SIGCONT},
        {"STOP", SIGSTOP},
        {"TSTP", SIGTSTP},
        {"TTIN", SIGTTIN},
        {"TTOU", SIGTTOU},
        {"URG", SIGURG},
        {"XCPU", SIGXCPU},
        {"XFSZ", SIGXFSZ},
        {"VTALRM", SIGVTALRM},
        {"PROF", SIGPROF},
        {"WINCH", SIGWINCH},
        {"IO", SIGIO},
        {"SYS", SIGSYS},
        /*senales que no hay en todas partes*/
#ifdef SIGPOLL
        { "POLL", SIGPOLL },
#endif
#ifdef SIGPWR
        { "PWR", SIGPWR },
#endif
#ifdef SIGEMT
        { "EMT", SIGEMT },
#endif
#ifdef SIGINFO
        { "INFO", SIGINFO },
#endif
#ifdef SIGSTKFLT
        { "STKFLT", SIGSTKFLT },
#endif
#ifdef SIGCLD
        { "CLD", SIGCLD },
#endif
#ifdef SIGLOST
        { "LOST", SIGLOST },
#endif
#ifdef SIGCANCEL
        { "CANCEL", SIGCANCEL },
#endif
#ifdef SIGTHAW
        { "THAW", SIGTHAW },
#endif
#ifdef SIGFREEZE
        { "FREEZE", SIGFREEZE },
#endif
#ifdef SIGLWP
        { "LWP", SIGLWP },
#endif
#ifdef SIGWAITING
        { "WAITING", SIGWAITING },
#endif
        {NULL, -1},
};

void createProcList(tProcList* list) {
    list->last = -1;
}

int insertProc(data proc, tProcList* list) {
    if (list->last == MAX_PROCL - 1) return 0;
    else {
        data * insert = (data *) malloc(sizeof(data));
        if (insert == NULL) {
            printf("Could not allocate memory\n");
            return 0;
        } else {
            *insert = proc;
            list->last++;
            list->data[list->last] = insert;
            return 1;
        }
    }
}

void clearProcList(tProcList* list) {
    for (int i = 0; i <= list->last; i++) {
        free(list->data[i]);
    }
    list->last = -1;
}

void updateProc(data* proc) {
    int state;
    proc->priority = getpriority(PRIO_PROCESS, proc->pid);
    if (waitpid(proc->pid, &state, WNOHANG |WUNTRACED |WCONTINUED) == proc->pid) {
        if (WIFCONTINUED(state)) strcpy(proc->state, "Running");
        else if (WIFSTOPPED(state)) {
            strcpy(proc->state, "Stopped");
            proc->returned_value = WSTOPSIG(state);
        } else if (WIFEXITED(state)) {
            proc->priority = -1;
            strcpy(proc->state, "Terminated Normally");
            proc->returned_value = WEXITSTATUS(state);
        } else if (WIFSIGNALED(state)) {
            proc->priority = -1;
            strcpy(proc->state, "Terminated By Signal");
            proc->returned_value = WTERMSIG(state);
        }
    }
}

int findProc(pid_t pid, tProcList list) {
    for (int i = 0; i <= list.last; i++) {
        if (list.data[i]->pid == pid) return i;
    }
    return -1;
}

data* getProc(tPos pos, tProcList list) {
    return list.data[pos];
}

int removeProcByPid(pid_t pid, tProcList* list) {
    int found = 0;
    if (list->last == -1) return 0;
    else {
        for (int i = 0; i <= list->last; i++) {
            if (!found) {
                if (pid == list->data[i]->pid) {
                    data *tmp = list->data[i];
                    free(tmp);
                    found = 1;
                }
            }
            if (found) list->data[i] = list->data[i+1];
        }
        if (found) {
            list->last--;
            return 1;
        }
        return 0;
    }
}

void updateProcList(tProcList* list) {
    for (int i = 0; i <= list->last; i++) {
        updateProc(list->data[i]);
    }
}

char * NombreSenal(int sen) /*devuelve el nombre senal a partir de la senal*/ {
    /* para sitios donde no hay sig2str*/
    int i;
    for (i = 0; sigstrnum[i].nombre != NULL; i++)
        if (sen == sigstrnum[i].senal)
            return sigstrnum[i].nombre;
    return ("SIGUNKNOWN");
}

void printProc(data proc) {
    struct tm *info;
    char buffer[50] = "";
    info = localtime(&proc.time);
    strftime(buffer, sizeof(buffer),"%Y/%m/%d %T", info);
    if ((strcmp(proc.state, "Terminated By Signal") != 0) & (strcmp(proc.state, "Stopped") != 0))
        printf(" %d priority=%d %s %s %s %s (%d)\n", proc.pid, proc.priority, proc.user, proc.command, buffer, proc.state, proc.returned_value);
    else {
        char senal[50] = "";
        strcpy(senal, NombreSenal(proc.returned_value));
        printf(" %d priority=%d %s %s %s %s (%s)\n", proc.pid, proc.priority, proc.user, proc.command, buffer, proc.state, senal);
    }
}

void showProcList(tProcList list) {
    for (int i = 0; i <= list.last; i++) {
        printProc(*list.data[i]);
    }
}

int checkData(char *rem_type, data proc) {
    if (strcmp(rem_type, "-all") == 0) {
        if ((strcmp(proc.state, "Terminated By Signal") == 0) | (strcmp(proc.state, "Terminated Normally") == 0)) return 1;
        return 0;
    } else {
        if (strcmp(rem_type, proc.state) == 0) return 1;
        return 0;
    }
}

int removeProcs(char *rem_type, tProcList* list) {
    int counter = 0, borrados = 0;
    if (list->last == -1) return 0;
    else {
        while (counter <= list->last) {
            if (borrados) list->data[counter] = list->data[counter + borrados];
            if (checkData(rem_type, *list->data[counter])) {
                data * tmp = list->data[counter];
                free(tmp);
                list->data[counter] = list->data[counter+1];
                list->last--;
                borrados++;
            } else counter++;
        }
        if (borrados) return 1;
        else return 0;
    }
}