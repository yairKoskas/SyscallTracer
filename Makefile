SRCDIR := src

all:
	gcc $(SRCDIR)/main.c $(SRCDIR)/handlers.c $(SRCDIR)/utils.c -o syscall_tracer
