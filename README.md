# Run the test.py script against the built test.c

## With the valid testblob
python -m pdb test.py test -a 0x4006F7 -if testblob

## Or random 32 bytes input
python -m pdb test.py test -a 0x4006F7 -is 32
