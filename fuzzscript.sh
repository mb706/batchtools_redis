
./redisfuzz.R ~/testdir watcher >fuzz/fuzztest_watcher.out 2>&1 &
sleep 10
./redisfuzz.R ~/testdir seeder 1 >fuzz/fuzztest_seeder_1.out 2>&1 &
sleep 3
./redisfuzz.R ~/testdir seeder 2 >fuzz/fuzztest_seeder_2.out 2>&1 &
./redisfuzz.R ~/testdir seeder 3 >fuzz/fuzztest_seeder_3.out 2>&1 &
sleep 5
./redisfuzz.R ~/testdir worker 4 >fuzz/fuzztest_worker_4.out 2>&1 &
./redisfuzz.R ~/testdir worker 5 >fuzz/fuzztest_worker_5.out 2>&1 &
./redisfuzz.R ~/testdir worker 6 >fuzz/fuzztest_worker_6.out 2>&1 &
./redisfuzz.R ~/testdir worker 7 >fuzz/fuzztest_worker_7.out 2>&1 &
./redisfuzz.R ~/testdir worker 11 >fuzz/fuzztest_worker_11.out 2>&1 &
sleep 10
./redisfuzz.R ~/testdir worker 1 >fuzz/fuzztest_worker_1_1.out 2>&1 &
sleep 10
./redisfuzz.R ~/testdir worker 1 >fuzz/fuzztest_worker_1_2.out 2>&1 &
sleep 10
./redisfuzz.R ~/testdir worker 1 >fuzz/fuzztest_worker_1_3.out 2>&1 &
./redisfuzz.R ~/testdir worker 4 >fuzz/fuzztest_worker_4_2.out 2>&1 &


./redisfuzz.R ~/testdir worker 1 >fuzz/fuzztest_worker_1_4.out 2>&1 &
./redisfuzz.R ~/testdir worker 1 >fuzz/fuzztest_worker_1_5.out 2>&1 &
./redisfuzz.R ~/testdir worker 1 >fuzz/fuzztest_worker_1_6.out 2>&1 &
./redisfuzz.R ~/testdir worker 1 >fuzz/fuzztest_worker_1_7.out 2>&1 &
