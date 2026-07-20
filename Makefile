CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
SRCS = src/main.c src/config.c src/check.c src/utils.c
OBJS = $(SRCS:.c=.o)
TARGET = baseline-guard

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TARGET)
	./test/test.sh

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all test clean