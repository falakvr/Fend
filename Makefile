CC = gcc
OPT = -O3
#OPT = -g
WARN = -Wall
CFLAGS = $(OPT) $(WARN) $(INC) $(LIB)

# List all your .cc files here (source files, excluding header files)
FEND_SRC = fend.c

# List corresponding compiled object files here (.o files)
FEND_OBJ = fend.o
 
#################################

# default rule

all: fend
	@echo "my work is done here..."


# rule for making fend

fend: $(FEND_OBJ)
	$(CC) -o fend $(CFLAGS) $(FEND_OBJ) -lm
	@echo "-----------DONE WITH FEND-----------"


# generic rule for converting any .cc file to any .o file
 
.cc.o:
	$(CC) $(CFLAGS)  -c $*.c


# type "make clean" to remove all .o files plus the fend binary

clean:
	rm -f *.o fend


# type "make clobber" to remove all .o files (leaves fend binary)

clobber:
	rm -f *.o


