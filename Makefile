CXX = g++
CXXFLAGS = -Wall -Wextra -g -I./include -std=c++17
LDFLAGS = -lfmt -lpthread

SRCS = src/main.cpp src/config.cpp src/check.cpp src/utils.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = baseline-guard

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

test: $(TARGET)
	./test/test.sh

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all test clean