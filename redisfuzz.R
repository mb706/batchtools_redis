#!/usr/bin/env Rscript

FUZZING <- TRUE
DEBUG <- TRUE

source("redisworker.R")

options(warn=1)

args <- commandArgs(trailingOnly = TRUE)

switch(args[2],
  watcher = {
    xcon <- redis.initiate(args[1])
  },
  worker = {
    xcon <- redis.initiate(args[1])
    wid <- assertCount(as.numeric(args[[3]]), positive = TRUE)
  },
  seeder = {
    xcon <- redis.initiate(args[1])
    wid <- assertCount(as.numeric(args[[3]]))
    jobindex <- 0
  },
  stopf("FUZZING. call with connection dir and then 'watcher', 'worker <accepting id>', or 'seeder <index>'")
)


repeat {
  tryCatch(withCallingHandlers({
      switch(args[2],
        watcher = {
          xcon <- redis.initiate(args[1])
          repeat {
            jobsq <- listJobsQueued(xcon)
            debugprint("Jobs queued:\n%s", paste(jobsq, collapse = ", "))
            jobsr <- listJobsRunning(xcon)
            debugprint("Jobs running:\n%s", paste(jobsr, collapse = ", "))
            Sys.sleep(10)
          }
        },
        worker = {
          xcon <- redis.initiate(args[1])
          plfun <- function(payload) {
            debugprint("FUZZING: Worker %s Evaluating payload (%s, %s)", wid, payload[[1]], payload[[2]])
            if (wid == 1) {
              debugprint("FUZZING: sleeping 6 s")
              Sys.sleep(6)
              debugprint("FUZZING: Worker 1 autoaccepts.")
              return(TRUE)
            } else {
              accepting <- payload[[1]] %% wid == 0
              debugprint("FUZZING: Worker %s %s.", wid, if (accepting) "ACCEPTS" else "REJECTS")
              return(accepting)
            }
          }
          evfun <- function(jobhandle, timeout) {
            debugprint("FUZZING: Running payload (%s, %s).", jobhandle[[1]], jobhandle[[2]])
            Sys.sleep(timeout)
            jobrun.present <- runif(1) > .7
          }
          worker(xcon, check.payload.fn = plfun, job.initfun = identity, job.evalfun = evfun, job.killfun = identity)
        },
        seeder = {
          xcon <- redis.initiate(args[1])
          repeat {
            jobindex <- jobindex + 1
            submitJob(xcon, c(jobindex, wid))
          }
        }, {
          cat("CRITICAL: this should not happen, just wasting time now.\n")
          Sys.sleep(100)
        }
      )
    }, error = function(e) {
      cat("FUZZING OUTER LOOP: caught error. Message: ")
      cat(e$message)
      cat("\ntraceback:\n")
      print(sys.calls())
    }
  ), error = function(e) {
    cat("FUZZING OUTER LOOP: Sleeping...\n")
    Sys.sleep(5)
    cat("FUZZING OUTER LOOP: Done\n")
  })
}

