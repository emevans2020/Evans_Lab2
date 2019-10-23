#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <glob.h>
#include "sh.h"

#define BUFFERSIZE 1028

void StringtoArray(char *input, char **cmds);

void StringtoArray(char *input, char **cmds)
{
	char *temp;
	temp = strtok(input, " ");
	if (temp == NULL)
	{

		cmds[0] = malloc(1 * sizeof(char));
		cmds[0][0] = 0;
		return;
	}
	int len = strlen(temp);
	cmds[0] = malloc(sizeof(char) * len + 1);
	strcpy(cmds[0], temp);
	int i = 1;
	while ((temp = strtok(NULL, " ")) != NULL)
	{
		len = strlen(temp);
		cmds[i] = malloc(sizeof(char) * len + 1);
		strcpy(cmds[i], temp);
		i++;
	}
	cmds[i] = NULL;
	free(cmds[i]);
}

int sh(int argc, char **argv, char **envp)
{
	char *prompt = calloc(PROMPTMAX, sizeof(char));
	char *commandline = calloc(MAX_CANON, sizeof(char));
	char *command, *arg, *commandpath, *p, *pwd, *owd, *cwd;
	char **args = calloc(MAXARGS, sizeof(char *));
	char cmd[64];
	int uid, i, status, errno, argsct, go = 1;
	struct passwd *password_entry;
	char *homedir;
	struct pathelement *pathlist;
	char *previousPath = malloc(1024 * sizeof(char));

	uid = getuid();
	password_entry = getpwuid(uid);   /* get passwd info */
	homedir = password_entry->pw_dir; /* Home directory to start out with*/

	if ((pwd = getcwd(NULL, PATH_MAX + 1)) == NULL)
	{
		perror("getcwd");
		exit(2);
	}

	cwd = calloc(strlen(pwd) + 1, sizeof(char));
	owd = calloc(strlen(pwd) + 1, sizeof(char));
	memcpy(owd, pwd, strlen(pwd));
	memcpy(cwd, pwd, strlen(pwd));
	prompt[0] = ' ';
	prompt[1] = '\0';

	/* Put PATH into a linked list */
	pathlist = get_path();

	//watches for Ctrl+C, Ctrl+Z
	signal(SIGINT, sigIntHandler);
	signal(SIGTSTP, sigStpHandler);
	signal(SIGTERM, sigStpHandler);

	while (go)
	{
		/* print your prompt */
		printf("%s%s >>", prompt, pwd);

		/* get command line and process */
		char buf[BUFFERSIZE];
		fgets(buf, BUFFERSIZE, stdin);
		int len = strlen(buf);
		buf[len - 1] = 0;

		StringtoArray(buf, args);

		/* get command line and process & also checks for ctrl D*/
		if (buf[0] == 0 || args[0] == NULL) {
			printf("Use exit to leave mysh.\n");
			continue;
		}

		else if (!strcmp(args[0], "exit"))
		{
			printf("Executing built-in %s\n", args[0]);
			free(cwd);
			free(owd);
			free(prompt);
			free(commandline);
			free(args);
			free(previousPath);
			free(pathlist);	
			go = 0;
		}
		else if (!strcmp(args[0], "which"))
		{
			char *path = which(args[1], pathlist);
			if (args[1] == NULL)
			{
				printf("Which needs an argument\n");
			}
			else
			{
				for (int i = 1; i < MAXARGS; i++)
				{
					if (args[i] != NULL)
					{
						char *path = which(args[i], pathlist);
						if (path)
						{
							// printf("hi");
							printf("%s\n", path);
							free(path);
						}
						else
						{
							printf("%s Could Not Find: %s\n", args[0], args[i]);
						}
					}
				}
			}
		} /* end of which */
		else if (!strcmp(args[0], "where"))
		{
			char *path = where(args[1], pathlist);
			if (args[1] == NULL)
			{
				printf("Where needs an argument\n");
			}
			else
			{
				for (int i = 1; i < MAXARGS; i++)
				{
					if (args[i] != NULL)
					{
						char *path = where(args[i], pathlist);
						if (path)
						{
							printf("%s\n", path);
							free(path);
						}
						else
						{
							printf("%s Could Not Find: %s\n", args[0], args[i]);
						}
					}
				}
			}
		} /* end of where */
		else if (!strcmp(args[0], "pwd"))
		{
			printf("Executing built-in %s\n", args[0]);
			printPWD();
		}

		else if (!strcmp(args[0], "printenv"))
		{ /*prints environment*/
			printf("Executing built-in %s\n", args[0]);
			//if proper amount of arguments
			if (args[0] != NULL && args[1] == NULL)
			{ /*prints whole environment*/
				int i = 0;
				while (envp[i] != NULL)
				{
					printf("%s\n", envp[i]);
					i++;
				}
			}
			else if (args[1] != NULL && args[2] == NULL)
			{ /*prints specificed env variable*/
				printenv(&args[1]);
			}
			//if passed in more than 2 arguments
			else
			{
				perror("printenv");
				printf("printenv: Too many arguments.\n");
			}
		}

		else if (!strcmp(args[0], "setenv"))
		{
			printf("Executing built-in %s\n", args[0]);

			if (args[0] != NULL && args[1] == NULL)
			{ /*prints whole environment if ran with no arguments*/
				int i = 0;
				while (envp[i] != NULL)
				{
					printf("%s\n", envp[i]);
					i++;
				}
			}
			// ran with one argument set that as an empty environment variable
			else if (args[1] != NULL && args[2] == NULL)
			{
				setEmptyEnv(args[1]);
			}
			// when ran with two arguments the second one is the value of the first
			else if (args[1] != NULL && args[2] != NULL && args[3] == NULL)
			{
				setValToEnv(args[1], args[2]);
				/*PATH special case, must free path list before setenv on PATH*/
				if (!strcmp(args[1], "PATH"))
				{
					free(pathlist);
					pathlist = get_path();
				}
				if (strcmp(args[1], "HOME") == 0)
				{
					homedir = getenv("HOME");
				}
			}
			else
			{ /* when ran with >2 args prints the same error message to stderr that tcsh does */
				perror("setenv");
				printf("setenv: Too many arguments.\n");
			}
		}

		else if (!strcmp(args[0], "cd"))
		{
			if (args[2])
			{
				fprintf(stderr, "Too many arguments\n");
			}
			if (!args[1])
			{
				chdir(getenv("HOME"));
				free(pwd);
				pwd = getcwd(NULL, PATH_MAX + 1);
			}
			else
			{
				if (args[1])
				{
					if (!strcmp(args[1], "-"))
					{
						strcpy(pwd, owd);
						free(owd);
						owd = getcwd(NULL, PATH_MAX + 1);
						chdir(pwd);
					}
					else
					{
						free(pwd);
						free(owd);
						owd = getcwd(NULL, PATH_MAX + 1);
						chdir(args[1]);
						pwd = getcwd(NULL, PATH_MAX + 1);
					}
				}
			}
		}

		else if (!strcmp(args[0], "pid"))
		{
			printf("Executing built-in %s\n", args[0]);
			printPid();
		}

		else if (!strcmp(args[0], "kill"))
		{
			if (args[0] != NULL && args[1] != NULL && args[2] == NULL)
			{
				killProcess(atoi(args[1]), 0);
			}
			else if (args[0] != NULL && args[1] != NULL && args[2] != NULL)
			{
				killProcess(atoi(args[2]), -1 * atoi(args[1]));
			}
		}

		else if (!strcmp(args[0], "list"))
		{
			printf("Executing built-in %s\n", args[0]);
			/*list everything if not args*/
			if (args[0] != NULL && args[1] == NULL && args[2] == NULL)
			{
				list(cwd);
			}
			else
			{
				/*lists for every folder passed in by user*/
				for (int i = 1; i < MAXARGS; i++)
				{
					if (args[i] != NULL)
					{
						printf("[%s]:\n", args[i]);
						list(args[i]);
					}
				}
			}
		}

		else if (!strcmp(args[0], "prompt"))
		{
			printf("Executing built-in %s\n", args[0]);
			newPrompt(args[1], prompt);
		}
		//call which to get the absolute path
		else
		{	 /* find it */
				char *cmd = which(args[0], pathlist); /* find it using which */
				int pid = fork();
				if (pid) /* do fork(), execve() and waitpid() */
				{
					free(cmd);
					waitpid(pid, NULL, 0);
				}
				else
				{
					//try to exec the absolute path
					// execve(cmd, args, envp);
					// printf("exec %s\n", args[0]);
					//Run the program.
					if (execve(cmd, args, envp) < 0)
					{
						//If execve() returns a negative value, the program could not be found.
						fprintf(stderr, "%s: Command not found.\n", args[0]);
						exit(0);
					}
				}
			}
	}
	return 0;
} /* sh() */

char *which(char *command, struct pathelement *pathlist)
{
	/* loop through pathlist until finding command and return it.  Return
   	NULL when not found. */
	char *result = malloc(BUFFERSIZE);
	while (pathlist)
	{ // WHICH
		sprintf(result, "%s/%s", pathlist->element, command);
		if (access(result, X_OK) == 0)
		{
			return result;
		}
		pathlist = pathlist->next;
	}
	free(result);
	return NULL;
} /* which() */

char *where(char *command, struct pathelement *pathlist)
{
	/* similarly loop through finding all locations of command */
	char *result = malloc(BUFFERSIZE);
	while (pathlist)
	{ // WHICH
		sprintf(result, "%s/%s", pathlist->element, command);
		if (access(result, F_OK) == 0)
		{
			return result;
		}
		pathlist = pathlist->next;
	}
	free(result);
	return NULL;
} /* where() */

void printPWD()
{
	char cwd[BUFFERSIZE];
	getcwd(cwd, sizeof(cwd));
	printf("%s\n", cwd);
} /* printPWD() */

void list(char *dir)
{ /* see man page for opendir() and readdir() and print out filenames for
  the directory passed */
	DIR *direct;
	struct dirent *dent;
	direct = opendir(dir);
	if (direct == NULL)
	{
		perror(dir);
	}
	else
	{
		while ((dent = readdir(direct)) != NULL)
		{
			printf("%s\n", dent->d_name);
		}
	}
	closedir(direct);
} /* list() */

void printenv(char **envp)
{
	char **currEnv = envp;
	printf("%s\n", getenv(*currEnv));
} /* printenv() */

void newPrompt(char *command, char *p)
{
	char buffer[BUFFERSIZE];
	int len;
	if (command == NULL)
	{
		command = malloc(sizeof(char) * PROMPTMAX);
		printf("Input new prompt prefix: ");
		if (fgets(buffer, BUFFERSIZE, stdin) != NULL)
		{
			len = (int)strlen(buffer);
			buffer[len - 1] = '\0';
			strcpy(command, buffer);
		}
		strcpy(p, command);
		free(command);
	}
	else
	{
		strcpy(p, command);
	}
} /* newPrompt() */

void printPid()
{
	printf("");
	int pid = getpid();
	printf("%d\n", pid);
} /* printPid() */

/* commands following set the environment */
void setEmptyEnv(char *name)
{
	setenv(name, "", 1);
}

void setValToEnv(char *arg1, char *arg2)
{
	// command to set environment when provided more than one command
	setenv(arg1, arg2, 1);
} /* setValToEnv() */
/* end of commands for set environment */

void killProcess(pid_t pid, int sig)
{
	if (sig == 0)
	{
		kill(pid, SIGTERM);
	}
	else
	{
		kill(pid, sig);
	}
}

/* signal handler functions below */
void sigIntHandler(int sig)
{
	/* Reset handler to catch SIGINT next time.*/
	signal(SIGINT, sigIntHandler);
	printf("\n Cannot be terminated using Ctrl+C %d \n", waitpid(getpid(), NULL, 0));
	fflush(stdout);
	return;
}

/*ctrl z handler*/
void sigStpHandler(int sig)
{
	signal(SIGTSTP, sigStpHandler);
	printf("\n Cannot be terminated using Ctrl+Z \n");
	fflush(stdout);
}
