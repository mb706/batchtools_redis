#!/usr/bin/env Rscript

Sys.setenv(OMP_NUM_THREADS="1")
Sys.setenv(OPENBLAS_NUM_THREADS="1")
Sys.setenv(MKL_NUM_THREADS="1")


library("checkmate")

args <- commandArgs(trailingOnly = TRUE)

if (!length(args) %in% c(3, 4) || !testNumber(as.numeric(args[[2]]), lower = 0) || !testNumber(as.numeric(args[[3]]))) {
  stop("Usage: <script> <redisdir> <mem available (mb)> <walltime (seconds)> [DEBUG]\n<mem available> and <walltime> may be 'Inf'.")
}

DEBUG <- FALSE
if (length(args) == 4) {
  if (args[[4]] != "DEBUG") stop("4th argument must be omitted, or must be 'DEBUG'.")
  DEBUG <- TRUE
  cat("Debug enabled\n")
}

options(warn=1)



source("redisqueue/redisworker.R")

workerBatchtools(args[[1]], mem.available = as.numeric(args[[2]]), walltime.available = as.numeric(args[[3]]))
