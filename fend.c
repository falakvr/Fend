#include <sys/ptrace.h>
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <pwd.h>

#define debug 0

char *config_file;
char *exec_file;
char *real_path_exec_file;
char actualpath_exec_file[PATH_MAX + 1];
char cwd[1024];
int file_in_cwd;
struct stat st;
DIR *dir;
struct dirent *entry;
FILE* fptr;
char *line;
size_t len = 0;
ssize_t readl;
int number_of_lines = 0;
char delimit[] = " \t\n"; //Whitespaces
int i = 0;
char *saveptr;
struct passwd *passwd;
char *new_str;

struct config {
	char *permission;
	char *filename;
};

void sandb_kill(pid_t pid, char **argv) {
	fprintf(stderr, "Terminating %s: unauthorized access of %s\n", argv[0],
			argv[1]);
	kill(pid, SIGKILL);
	wait(NULL);
	exit(EXIT_FAILURE);
}

char *read_string(pid_t child, unsigned long long int addr) {
	char *val = malloc(4096);
	int allocated = 4096;
	int read = 0;
	unsigned long tmp;
	while (1) {
		if (read + sizeof tmp > allocated) {
			allocated *= 2;
			val = realloc(val, allocated);
		}
		tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
		if (errno != 0) {
			val[read] = 0;
			break;
		}
		memcpy(val + read, &tmp, sizeof tmp);
		if (memchr(&tmp, 0, sizeof tmp) != NULL)
			break;
		read += sizeof tmp;
	}
	return val;
}

void sandb_handle_syscall(pid_t pid, int number_of_lines,
		struct config *config_array, char **argv) {
	struct user_regs_struct regs;
	char *strval;
	int flag;
	char actualpath[PATH_MAX + 1];
	char *real_path;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

	if (regs.orig_rax == 2) {

		//OPEN syscall

		strval = read_string(pid, regs.rdi);

		flag = (regs.rsi & O_ACCMODE);

		for (i = 0; i < number_of_lines; i++) {
			if (fnmatch(config_array[i].filename, strval, FNM_PATHNAME) == 0) {
				//permi = config_array[i].permission;
				if (flag == O_RDONLY) {
					if (config_array[i].permission[0] == '0') {
						sandb_kill(pid, argv);
					}
				} else if (flag == O_WRONLY) {
					if (config_array[i].permission[1] == '0') {
						sandb_kill(pid, argv);
					}
				} else if (flag == O_RDWR) {
					if (!(config_array[i].permission[0] == '1'
							&& config_array[i].permission[1] == '1')) {
						sandb_kill(pid, argv);
					}
				}
			}
		}
	}

	if (regs.orig_rax == 257) {

		strval = read_string(pid, regs.rsi);
		real_path = realpath(strval, actualpath);

		flag = (regs.rdx & O_ACCMODE);

		for (i = 0; i < number_of_lines; i++) {
			if ((fnmatch(config_array[i].filename, real_path, FNM_PATHNAME) == 0)) {
				if (flag == O_RDONLY) {
					if (config_array[i].permission[0] == '0') {
						sandb_kill(pid, argv);
					}
				} else if (flag == O_WRONLY) {
					if (config_array[i].permission[1] == '0') {
						sandb_kill(pid, argv);
					}
				} else if (flag == O_RDWR) {
					if (!(config_array[i].permission[0] == '1'
							&& config_array[i].permission[1] == '1')) {
						sandb_kill(pid, argv);
					}
				}
			}
		}
	}

}

void sandb_run(pid_t pid, int number_of_lines, struct config *config_array,
		char *real_path_exec_file, char **argv) {
	struct user_regs_struct regs;
	int i = 0;

	int status;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

	if (regs.orig_rax == 59) {

		//execve

		if (real_path_exec_file != NULL) {
			for (i = 0; i < number_of_lines; i++) {
				if ((fnmatch(config_array[i].filename, real_path_exec_file,
				FNM_PATHNAME) == 0)) {
					if (config_array[i].permission[2] == '0') {
						sandb_kill(pid, argv);
					}
				}
			}
		}
	}

	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
		if (errno == ESRCH) {
			waitpid(pid, &status, __WALL | WNOHANG);
			sandb_kill(pid, argv);
		} else {
			err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
		}
	}
	wait(&status);

	if (WIFEXITED(status)) {
		exit(EXIT_SUCCESS);
	}

	if (WIFSTOPPED(status)) {
		sandb_handle_syscall(pid, number_of_lines, config_array, argv);
	}
}

int main(int argc, char *argv[]) {

	if (argc < 2) {
		errx(EXIT_FAILURE, "[SANDBOX] Usage : %s -c <config_file> [<arg1...>]", argv[0]);
	}

	if ((argc == 2) && (strcmp(argv[1], "-c") != 0)) {
		exec_file = argv[1];
		real_path_exec_file = realpath(exec_file, actualpath_exec_file);
		if (debug)
			printf("%s\n", real_path_exec_file);
	}

	if (0 == strcmp(argv[1], "-c")) {
		if (argc == 4) {

			exec_file = argv[3];
			real_path_exec_file = realpath(exec_file, actualpath_exec_file);
			if (debug)
				printf("%s\n", real_path_exec_file);

		} else {
			config_file = argv[2];
			argv = argv + 3;
			argc = argc - 3;

			//read config file

			fptr = fopen(config_file, "r");
		}
	}

	else {
		argv = argv + 1;
		argc = argc - 1;
		config_file = ".fendrc";

		// find .fendrc in current working directory else in the home directory

		//current directory

		getcwd(cwd, sizeof(cwd));

		file_in_cwd = stat(config_file, &st);

		//http://stackoverflow.com/questions/230062/whats-the-best-way-to-check-if-a-file-exists-in-c-cross-platform

		if (file_in_cwd != -1) {
			fptr = fopen(config_file, "r");
		} else {

			//look in home directory;
			config_file = "/.fendrc";
			passwd = getpwuid(getuid());

			if ((new_str = malloc(
					strlen(passwd->pw_dir) + strlen(config_file) + 1)) != NULL) {
				new_str[0] = '\0';   // ensures the memory is an empty string
				strcat(new_str, passwd->pw_dir);
				strcat(new_str, config_file);
			} else {
				fprintf(stderr, "malloc failed!\n");
				// exit?
			}

			if (access(new_str, F_OK) != -1) {
				// file exists
				fptr = fopen(new_str, "r");
			} else {
				// file doesn't exist
				printf("Must provide a config file.\n");
			}

		}
	}

	if (fptr == NULL) {
		exit(EXIT_FAILURE);
	}

	while ((readl = getline(&line, &len, fptr)) != -1) {
		number_of_lines++;
	}

	struct config *config_array = (struct config*) malloc(
			sizeof(struct config) * number_of_lines);

	rewind(fptr);

	for (i = 0; i < number_of_lines; i++) {
		getline(&line, &len, fptr);
		char * foo = strtok(line, delimit);
		config_array[i].permission = strdup(foo);

		char * bar = strtok(NULL, delimit);
		config_array[i].filename = strdup(bar);
	}

	pid_t pid;

	pid = fork();

	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
			err(EXIT_FAILURE, "FEND Failed to PTRACE_TRACEME:");

		if (execvp(argv[0], argv) < 0)
			err(EXIT_FAILURE, "[SANDBOX] Failed to execv:");
	} else {
		wait(NULL);
	}

	for (;;) {
		sandb_run(pid, number_of_lines, config_array, real_path_exec_file,
				argv);
	}
	exit(EXIT_SUCCESS);
}