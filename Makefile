# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -Wno-format -Wno-format-truncation

# Dynamically find only the .c files that physically exist in the folder right now
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

# Windows Core DLL Hooks & Parsers
LIBS = -lpsapi -lversion -ldbghelp

# Target Executable Name
TARGET = VMProtectDumper.exe

# Default target
all: $(TARGET)

# Final Linking Phase (Only ties together existing files)
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

# Compilation Rule
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean Routine safely isolated for multi-platform shells
clean:
	@del /Q *.o $(TARGET) 2>nul || rm -f *.o $(TARGET)
