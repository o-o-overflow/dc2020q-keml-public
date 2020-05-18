TARGET = keml
TARGETUSER = $(TARGET)user

obj-m += $(TARGET).o

BUILD :=

all: userspace
	make -C ../../../linux M=$(PWD) modules
	cp $(TARGET).ko ../../..

userspace:
	$(CC) $(TARGETUSER).c -o $(TARGETUSER) -lpthread -static
	cp $(TARGETUSER) ../../../initramfs/home/user/

clean:
	make -C ../../../linux M=$(PWD) clean
