CXX = g++
CXXFLAGS = -std=c++17 -Wall -Iinclude -O2

TARGETS = main test
OBJS = sha256.o
TEST_VECTORS = test_vectors.json

all: $(TARGETS)

run: test
	clear 
	./test

main: main.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ main.cpp $(OBJS)

sha256.o: src/sha256.cpp include/sha256.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: tests/test_sha256.cpp $(OBJS) generate
	$(CXX) $(CXXFLAGS) -o $@ $< $(OBJS)
	
$(TEST_VECTORS):
	python3 run_sha256_tests.py --generate-only

generate: $(TEST_VECTORS)

python_test: 
	python3 run_sha256_tests.py 

valgrind_build:
	$(MAKE) clean
	$(MAKE) CXXFLAGS="$(CXXFLAGS) -DSKIP_LARGE_SHA256_TEST"

valgrind: valgrind_build
	valgrind --leak-check=full --track-origins=yes ./main
	valgrind --leak-check=full --track-origins=yes ./test

clean:
	rm -f *.o $(TARGETS) *.json

.PHONY: all clean generate valgrind