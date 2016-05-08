#If you use threads, add -pthread here.
COMPILERFLAGS = -std=c++11 -Wall -Wextra -Wno-sign-compare

#Any libraries you might need linked in.
LINKLIBS = -lprotobuf -lpolarssl -L/usr/lib64 -lstdc++ -lmbedcrypto

#The components of each program. When you create a src/foo.c source file, add obj/foo.o here, separated
#by a space (e.g. SOMEOBJECTS = obj/foo.o obj/bar.o obj/baz.o).
CONVERTEROBJECTS = obj/client_handler_session.o obj/globals.o obj/base64.o obj/main.o obj/insecure_memzero.o obj/sha256.o obj/polar_tls_client.o obj/polar_tls_server.o obj/polar_tls_session.o obj/utility.o obj/pamrac.pb.o obj/handle_init_blob_request.o obj/handle_blob_request.o obj/handle_blob_upload.o obj/handle_init_share_list_request.o obj/handle_init_share_request.o obj/handle_init_share_upload.o obj/handle_init_upload_request.o obj/handle_share_list_request.o obj/handle_share_request.o obj/handle_share_upload.o obj/crypto.o obj/handle_connect_new_store.o obj/client_store.o


#Every rule listed here as .PHONY is "phony": when you say you want that rule satisfied,
#Make knows not to bother checking whether the file exists, it just runs the recipes regardless.
#(Usually used for rules whose targets are conceptual, rather than real files, such as 'clean'.
#If you DIDNT mark clean phony, then if there is a file named 'clean' in your directory, running
#make clean would do nothing!!!)
.PHONY: all clean

#The first rule in the Makefile is the default (the one chosen by plain `make`).
all : obj server



server: $(CONVERTEROBJECTS)
	$(CC) $(COMPILERFLAGS) $^ -o $@ $(LINKLIBS)
	

#RM is a built-in variable that defaults to "rm -f".
clean :
	$(RM) obj/*.o server

#$<: the first dependency in the list; here, src/%.c. (Of course, we could also have used $^).
#The % sign means "match one or more characters". You specify it in the target, and when a file
#dependency is checked, if its name matches this pattern, this rule is used. You can also use the % 
#in your list of dependencies, and it will insert whatever characters were matched for the target name.
obj/%.o: src/%.cc
	$(CC) $(COMPILERFLAGS) -c -o $@ $<
obj:
	mkdir -p obj
