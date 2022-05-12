CC = gcc
STRIP = strip 
LDFLAGS = -Wall -fPIC -O2 -g
CFLAGS = -L ../dms_sdf_code -Wl,-rpath=../dms_sdf_code
#CFLAGS =  -Wall -O2  -L /usr/local/dms_pci_sdf/lib/ -Wl,-rpath=/usr/local/dms_pci_sdf/lib/
LIBS +=  -ldl   -lm -rdynamic -lpthread -lpcisdf
#include 
INCLUDE = -I ./src -I ../dms_sdf_code/include -I ./src/alg
#define

# target source
SUBDIR =  ./src ./src/alg
CSRCS  = $(foreach dir,$(SUBDIR),$(wildcard $(dir)/*.c))
OBJS   = $(CSRCS:%.c=%.o)

$(warning $(CSRCS))

TARGET := dms_sdf_test
.PHONY : clean all

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(INCLUDE) -o $@ $^ $(LIBS) $(LDFLAGS) $(CFLAGS) 
	$(STRIP) $@

.SUFFIXES: .o .c .C

.c.o:
	$(CC) -c -Wall  $(INCLUDE) -o "$@" "$<" -std=c99 $(LDFLAGS)

clean:
	@rm -f $(TARGET)
	@rm -f $(OBJS)
