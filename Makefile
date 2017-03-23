CC = g++ 
CFLAGS = -std=c++98 -pedantic -Wall -W -O2 -Wextra
all: myripresponse myripsniffer myriprequest

myripresponse: myripresponse.cpp
	$(CC) $(CFLAGS) -o $@ myripresponse.cpp -lpcap
	
myripsniffer: myripsniffer.cpp
	$(CC) $(CFLAGS) -o $@ myripsniffer.cpp -lpcap
	
myriprequest: myriprequest.cpp
	$(CC) $(CFLAGS) -o $@ myriprequest.cpp -lpcap
	
clean:
	rm -f *.o *.out myripresponse myripsniffer
	
remove: 
	rm *.o *.out
