CXX = g++
CXXFLAGS = -g -Wall -Wextra -pedantic -march=x86-64
ODIR = ./bin

SRCS = main.cpp
OBJS = $(SRCS:.cpp=.o)

${ODIR}/main: $(OBJS) c3_model.h
	$(CXX) $(CXXFLAGS) $(OBJS) -o ./bin/main

.PHONY: clean

clean:
	rm -f $(OBJS) ./bin/*
