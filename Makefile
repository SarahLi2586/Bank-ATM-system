JC = javac

SOURCES = $(wildcard *.java)

CLASSES = $(SOURCES:.java=.class)

all: $(CLASSES)

$(CLASSES): $(SOURCES)
	$(JC) $(SOURCES)

clean:
	rm -f *.class