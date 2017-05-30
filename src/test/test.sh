#!/bin/sh

make
./a.out
#Install gcovr with: pip install gcovr
gcovr -r . --html -o coverage.html --html-details

rm -rf data/
mkdir data/
mv *.gcda data/
mv *.html data/
mv a.out data/test.out
mv *.gcno data/
mv *.gch data/
mv *.o data/



