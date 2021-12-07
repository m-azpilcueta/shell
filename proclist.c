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

void showProcList(tProcList list) {
    struct tm *info;
    char buffer[50];
    char senal[50];
    for (int i = 0; i <= list.last; i++) {
        info = localtime(&list.data[i]->time);
        strftime(buffer,sizeof(buffer),"%Y/%m/%d %T",info);
        strcpy(senal, NombreSenal(list.data[i]->returned_value));
        if ((strcmp(list.data[i]->state, "Terminated By Signal") != 0) & (strcmp(list.data[i]->state, "Stopped") != 0))
            printf(" %d priority=%d %s %s %s %s (%d)\n", list.data[i]->pid, list.data[i]->priority, list.data[i]->user, list.data[i]->command, buffer, list.data[i]->state, list.data[i]->returned_value);
        else
            printf(" %d priority=%d %s %s %s %s (%s)\n", list.data[i]->pid, list.data[i]->priority, list.data[i]->user, list.data[i]->command, buffer, list.data[i]->state, senal);
    }
}