#If you use threads, add -pthread here.
COMPILERFLAGS = -std=c++11 -Wall -Wextra -Wno-sign-compare

#Any libraries you might need linked in.
LINKLIBS = -lprotobuf -L/usr/lib64 -lstdc++

#The components of each program. When you create a src/foo.c source file, add obj/foo.o here, separated
#by a space (e.g. SOMEOBJECTS = obj/foo.o obj/bar.o obj/baz.o).
CONVERTEROBJECTS = obj/conversion_interface.o obj/pamrac.pb.o obj/textfile_converter.o obj/aes.o obj/base64.o obj/crypto_scrypt.o obj/insecure_memzero.o obj/sha256.o 



#Every rule listed here as .PHONY is "phony": when you say you want that rule satisfied,
#Make knows not to bother checking whether the file exists, it just runs the recipes regardless.
#(Usually used for rules whose targets are conceptual, rather than real files, such as 'clean'.
#If you DIDNT mark clean phony, then if there is a file named 'clean' in your directory, running
#make clean would do nothing!!!)
.PHONY: all clean

#The first rule in the Makefile is the default (the one chosen by plain `make`).
all : obj converter



converter: $(CONVERTEROBJECTS)
	$(CC) $(COMPILERFLAGS) $^ -o $@ $(LINKLIBS)
	

#RM is a built-in variable that defaults to "rm -f".
clean :
	$(RM) obj/*.o converter

#$<: the first dependency in the list; here, src/%.c. (Of course, we could also have used $^).
#The % sign means "match one or more characters". You specify it in the target, and when a file
#dependency is checked, if its name matches this pattern, this rule is used. You can also use the % 
#in your list of dependencies, and it will insert whatever characters were matched for the target name.
obj/%.o: src/%.cc
	$(CC) $(COMPILERFLAGS) -c -o $@ $<
obj:
	mkdir -p obj
