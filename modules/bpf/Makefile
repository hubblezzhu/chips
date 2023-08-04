

LLC ?= llc
CLANG ?= clang
OPT ?= opt
RM ?= rm

bpf_prog-y := stack.bpf.o
# bpf_prog-y += xxx.bpf.o

CLANG_FLAGS := -g -O2
CLANG_FLAGS += -Wall --target=bpf -emit-llvm -fPIC -D_FORTIFY_SOURCE=2

# arch
ARCH ?= $(shell uname -m)

ifeq ($(ARCH),x86_64)
    CLANG_FLAGS += -D__x86_64__
endif

ifeq ($(ARCH), aarch64)
    CLANG_FLAGS += -D__aarch64__
endif

INCLUDE_FLAGS :=  -I.
INCLUDE_FLAGS +=  -I/usr/include/bpf


.PHONY: all
all: $(bpf_prog-y)

%.o: %.c
	$(CLANG) $(CLANG_FLAGS) $(INCLUDE_FLAGS) -c $< -o $@

.PHONY: clean
clean:
	$(RM) -f *.o *~
