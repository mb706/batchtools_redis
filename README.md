# Use `redis` to schedule BatchTools jobs

Solves a few problems that batchtools generates in some environments, e.g. too many individual jobs.
Instead of making batchtools schedule slurm-jobs, you can then run btworker.R within slurm and have batchtools schedule jobs on redis. 
Make sure you know what you are doing, or you may be disturbing other users if you are on a time sharing cluster.

The redis-server is launched by runredis.sh, then workers need to be run by `btworker.R`.
If workload e.g. is single-core, launch one btworker.R per core etc.

Requirements: `redis`, `socat`, `batchtools`.

This repo is probably not useful in its current state, I hope I will have time to improve it at some point.
When using it, make sure you know what you are doing.
The code is horrible and I would write it differently now.
It is mostly like this since I was working with an old version of redis that did not provide a few necessary features.

# License

MIT
