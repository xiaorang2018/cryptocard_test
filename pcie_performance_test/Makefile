PciGUOMI_INC=-I /root/dms_pci_sdf/include
PciGUOMI_LIB=-L /root/dms_pci_sdf/lib/


all:  *.c
	gcc -w -o xnTest $(PciGUOMI_INC) $(PciGUOMI_LIB) $^  -lm -lpcisdf -lpthread -DDMS_DEBUG   -Wl,-rpath=/usr/local/PciGUOMI/lib/PciGUOMI.so
