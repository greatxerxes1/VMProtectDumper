# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -O2

# Target Executable Name
TARGET = VMProtectDumper.exe

# Automatically gather all .c files in the root folder
SRCS = VMProtectDumper.c dll_launcher.c dropper.c hooks.c iat_rebuild.c monitor.c pe_parser.c reports.c
OBJS = $(SRCS:.c=.o)

# Default Rule
all: $(TARGET)

# Link Object Files into the Final Executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

# Compile Source Files to Object Files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean Up Generated Files
clean:
	del /Q *.o $(TARGET) 2>nul || rm -f *.o $(TARGET)

