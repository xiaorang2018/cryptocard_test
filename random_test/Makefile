all:
	gcc *.c -g -o test -I /usr/local/PciGUOMI/include -L /usr/local/PciGUOMI/lib -lPciGUOMI -Wl,-rpath=/usr/local/PciGUOMI/lib -lsts -lm -DDMS_DEBUG

clean:
	rm -f *.o main
