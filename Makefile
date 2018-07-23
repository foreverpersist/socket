#Makefile

CC := gcc 

TARGETS := chatroom ever client server test

LIB := -lpthread

FLAG := -Werror

all: $(TARGETS)

$(TARGETS): %: %.o sock.o
	$(CC) $(FLAG) -o $@ $^ $(LIB)

%.o: %.c
	$(CC) $(FLAG) -c -o $@ $^

clean:
	-rm $(TARGETS)
	-rm *.o
