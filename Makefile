# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -Wno-format -Wno-format-truncation

# Core Windows Libraries required for Hooking, Process manipulation, and Minidumps
LIBS = -lpsapi -lversion -ldbghelp

# Target Executable Name
TARGET = VMProtectDumper.exe

# Source and Object files
SRCS = VMProtectDumper.c dll_launcher.c dropper.c hooks.c iat_rebuild.c monitor.c pe_parser.c reports.c
OBJS = $(SRCS:.c=.o)

# Default Rule
all: $(TARGET)

# Link Object Files with Windows API Libraries into the Final Executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

# Compile Source Files to Object Files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean Up Generated Files
clean:
	@del /Q *.o $(TARGET) 2>nul || rm -f *.o $(TARGET)
