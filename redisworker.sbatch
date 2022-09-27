#!/bin/bash

# output: relative to directory
#SBATCH -o redislog/%x.%J.%N.%t.out
#SBATCH -D ./

#SBATCH --export=ALL

#SBATCH --partition=gpu_interactive

# maximum time
#SBATCH --time=2-00:00:00
# max memory
#SBATCH --mem=60G
#SBATCH --nodes=1
#SBATCH --cpus-per-task=4
#SBATCH -G 1

echo SELF-SCHEDULING
sbatch "--dependency=afterany:${SLURM_JOBID}" "$SLURM_JOB_NAME"
echo RUNNING

sleep 60
# timeout 2 days, minus 5 minutes safety
./btworker.R redisdir 61440 $((2 * 24 * 60 * 60 - 300)) DEBUG 2>&1

echo DONE. returnvalue: $?
