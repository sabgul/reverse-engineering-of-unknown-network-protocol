CFLAGS = -std=c++17 -g
LFLAGS = -lpcap -Wall
X = client

$(X): $(X).o
	g++ $(CFLAGS) -o $(X) $(X).o $(LFLAGS)

$(X).o: $(X).cpp
	g++ $(CFLAGS) -c -o $(X).o $(X).cpp

clean:
	rm -f $(X) $(X).o
