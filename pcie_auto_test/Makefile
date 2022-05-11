INC=-I /usr/local/cunit/include/CUnit/
PciGUOMI_INC=-I /root/dms_pci_sdf/include/
LIB=-L /usr/local/cunit/lib/ 
PciGUOMI_LIB=-L /root/dms_pci_sdf/lib/


all:  *.c
	gcc -w -g -o  pcieTest $(INC) $(LIB) $(PciGUOMI_INC) $(PciGUOMI_LIB) $^ -lcunit -lm -lpcisdf -std=c++11 -pthread  -Wl,-rpath=/usr/local/PciGUOMI/lib/pcisdf.so

