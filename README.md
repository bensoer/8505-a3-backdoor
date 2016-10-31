#8505-a3-backdoor
8505-a3-backdoor is a Linux based backdoor program that once installed allows remote access to the
target machine

#Setup
##Prerequisites
In order to compile and run the backdoor and client you will need cmake installed on your machine
##Installation
Execute the following commands from the project root to build the server

1. `cd ./Server/src`
2. `cmake CMakeLists.txt`
3. The compiled binary will be located in the `/Server/bin` folder
4. Execute the server with no parameters to see all configuration options available

Execute the following commands from the project root to build the client

1. `cd ./Client/src`
2. `cmake CMakeLists.txt`
3. The compiled binary will be located in the `/Client/bin` folder
4. Execute the client with the `-h` parameter to see all configuration options available


#Testing
Tests have been carried out in the /docs/TestDocument.pdf file. This gives a high level of each test and their results.
Screenshots for each test can then be found in the /docs/tests folder followed by the ID name of the test as the folder
name. Within each folder contains screenshots displaying the results of the test.
