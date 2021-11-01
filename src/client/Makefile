# CFLAGS = -std=gnu99 -Wall -pedantic
# LFLAGS = -lpcap
CFLAGS = -g -Wall
X = client
$(X): $(X).o
	gcc $(CFLAGS) -o $(X) $(X).o $(LFLAGS)

$(X).o: $(X).cpp
	gcc $(CFLAGS) -c -o $(X).o $(X).cpp

clean:
	rm -f $(X) $(X).o