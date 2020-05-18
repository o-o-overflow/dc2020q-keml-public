from ubuntu:18.04

# example:
run apt-get -qq update && apt-get install -qq --no-install-recommends xinetd qemu-system-x86 socat
# python3-pip, etc.

copy service.conf /service.conf
copy banner_fail /banner_fail
copy wrapper /wrapper

copy bzImage /
copy initramfs.cpio.gz /

copy server /

expose 5000
#cmd ["/usr/sbin/xinetd", "-syslog", "local0", "-dontfork", "-f", "/service.conf"]
cmd ["/server"]
# ^^ If ps would be too revealing, replace with the line below.
#    AFAIK, this also disables the built-in printf(%n) protection, so YMMV.
#cmd chmod go-rwx /proc && /usr/sbin/xinetd -syslog local0 -dontfork -f /service.conf
