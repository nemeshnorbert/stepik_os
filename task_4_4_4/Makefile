# Primary compiler
CC := g++

SRCDIR := src
INCLUDEDIR = include
BUILDDIR := build
TARGETDIR := bin

SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name \*.$(SRCEXT) ! -name main.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
TARGET := $(TARGETDIR)/main
CFLAGS := -g -Wall -std=c++17
LIB :=
INC := -I $(INCLUDEDIR)

all: $(TARGET)

$(TARGET): dirs $(OBJECTS)
	$(CC) $(CFLAGS) $(INC) $(LIB) -o $@ $(SRCDIR)/main.$(SRCEXT) $(filter-out dirs, $^)

dirs:
	@mkdir -p $(BUILDDIR)
	@mkdir -p $(TARGETDIR)
	@mkdir -p $(INCLUDEDIR)

$(BUILDDIR)/%.o: dirs $(SRCDIR)/%.$(SRCEXT)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $(word 2, $^)

clean:
	rm -rvf $(BUILDDIR) $(TARGETDIR)/*;

.PHONY: all clean
