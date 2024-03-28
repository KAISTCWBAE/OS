cd ..
make
cd build
pintos -v -- -q run alarm-priority
pintos -v -k -T 480 -m 20   -- -q  -mlfqs run mlfqs-nice-10